package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DMarby/jitter"
	"github.com/infosum/statsd"
	"github.com/jamiealquiza/envy"
	"github.com/mullvad/wireguard-manager/api"
	"github.com/mullvad/wireguard-manager/portforward"
	"github.com/mullvad/wireguard-manager/wireguard"
)

var (
	a          *api.API
	wg         *wireguard.Wireguard
	pf         *portforward.Portforward
	metrics    *statsd.Client
	appVersion string // Populated during build time
)

func main() {
	// Set up commandline flags
	interval := flag.Duration("interval", time.Minute, "how often wireguard peers will be synchronized with the api")
	delay := flag.Duration("delay", time.Second*45, "max random delay for the synchronization")
	url := flag.String("url", "https://api.mullvad.net", "api url")
	username := flag.String("username", "", "api username")
	password := flag.String("password", "", "api password")
	interfaces := flag.String("interfaces", "wg0", "wireguard interfaces to configure. Pass a comma delimited list to configure multiple interfaces, eg 'wg0,wg1,wg2'")
	portForwardingChain := flag.String("portforwarding-chain", "PORTFORWARDING", "iptables chain to use for portforwarding")
	portForwardingIpsetIPv4 := flag.String("portforwarding-ipset-ipv4", "PORTFORWARDING_IPV4", "ipset table to use for portforwarding for ipv4 addresses.")
	portForwardingIpsetIPv6 := flag.String("portforwarding-ipset-ipv6", "PORTFORWARDING_IPV6", "ipset table to use for portforwarding for ipv6 addresses.")
	statsdAddress := flag.String("statsd-address", "127.0.0.1:8125", "statsd address to send metrics to")

	// Parse environment variables
	envy.Parse("WG")

	// Add flag to output the version
	version := flag.Bool("v", false, "prints current app version")

	// Parse commandline flags
	flag.Parse()

	if *version {
		fmt.Println(appVersion)
		os.Exit(0)
	}

	log.Printf("starting wireguard-manager %s", appVersion)

	// Initialize metrics
	var err error
	metrics, err = statsd.New(statsd.TagsFormat(statsd.Datadog), statsd.Prefix("wireguard"), statsd.Address(*statsdAddress))
	if err != nil {
		log.Fatalf("Error initializing metrics %s", err)
	}
	defer metrics.Close()

	// Initialize the API
	a = &api.API{
		Username: *username,
		Password: *password,
		BaseURL:  *url,
		Client: &http.Client{
			Timeout: time.Second * 10, // By default http.Client doesn't have a timeout, so specify a reasonable one
		},
	}

	// Initialize Wireguard
	if *interfaces == "" {
		log.Fatalf("no wireguard interfaces configured")
	}

	interfacesList := strings.Split(*interfaces, ",")

	wg, err = wireguard.New(interfacesList, metrics)
	if err != nil {
		log.Fatalf("error initializing wireguard %s", err)
	}
	defer wg.Close()

	// Initialize portforward
	pf, err = portforward.New(*portForwardingChain, *portForwardingIpsetIPv4, *portForwardingIpsetIPv6)
	if err != nil {
		log.Fatalf("error initializing portforwarding %s", err)
	}

	// Set up context for shutting down
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()

	// Run an initial synchronization
	synchronize()

	// Create a ticker to run our logic for polling the api and updating wireguard peers
	ticker := jitter.NewTicker(*interval, *delay)
	go func() {
		for {
			select {
			case <-ticker.C:
				// We run this synchronously, the ticker will drop ticks if this takes too long
				// This way we don't need a mutex or similar to ensure it doesn't run concurrently either
				synchronize()
			case <-shutdownCtx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	// Wait for shutdown or error
	err = waitForInterrupt(shutdownCtx)
	log.Printf("shutting down: %s", err)
}

func synchronize() {
	defer metrics.NewTiming().Send("synchronize_time")

	t := metrics.NewTiming()
	peers, err := a.GetWireguardPeers()
	if err != nil {
		metrics.Increment("error_getting_peers")
		log.Printf("error getting peers %s", err.Error())
		return
	}
	t.Send("get_wireguard_peers_time")

	t = metrics.NewTiming()
	wg.UpdatePeers(peers)
	t.Send("update_peers_time")

	t = metrics.NewTiming()
	pf.UpdatePortforwarding(peers)
	t.Send("update_portforwarding_time")
}

func waitForInterrupt(ctx context.Context) error {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-c:
		return fmt.Errorf("received signal %s", sig)
	case <-ctx.Done():
		return errors.New("canceled")
	}
}
