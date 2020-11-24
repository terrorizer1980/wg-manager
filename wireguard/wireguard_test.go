package wireguard_test

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/infosum/statsd"
	"github.com/mullvad/wg-manager/api"
	"github.com/mullvad/wg-manager/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Integration tests for wireguard, not ran in short mode
// Requires a wireguard interface named wg0 to be running on the system

const testInterface = "wg0"
const testClientInterface = "wg1"

var listenPort int = 4200
var keepAliveInterval = time.Second

var _, ipv4Net, _ = net.ParseCIDR("10.99.0.1/32")
var _, ipv4ClientNet, _ = net.ParseCIDR("10.99.0.2/32")
var ipv4IP = net.ParseIP("10.99.0.1")
var ipv6Net = net.ParseIP("fc00:bbbb:bbbb:bb01::")

var apiFixture = api.WireguardPeerList{
	api.WireguardPeer{
		IPv4:   "10.99.0.1/32",
		IPv6:   "fc00:bbbb:bbbb:bb01::1/128",
		Ports:  []int{1234, 4321},
		Pubkey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
	},
}

var peerFixture = []wgtypes.Peer{{
	PublicKey: wgKey(),
	AllowedIPs: []net.IPNet{
		{
			IP:   ipv4IP,
			Mask: net.CIDRMask(32, 32),
		},
		{
			IP:   net.ParseIP("fc00:bbbb:bbbb:bb01::1"),
			Mask: net.CIDRMask(128, 128),
		},
	},
	ProtocolVersion: 1,
}}

func wgKey() wgtypes.Key {
	key, _ := wgtypes.NewKey([]byte(strings.Repeat("a", 32)))
	return key
}

func TestWireguard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests")
	}

	metrics, err := statsd.New()
	if err != nil {
		t.Fatal(err)
	}

	client, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}

	defer client.Close()
	defer resetDevice(t, client)

	wgPrivkey, _ := wgtypes.GeneratePrivateKey()
	wgClientPrivkey, _ := wgtypes.GeneratePrivateKey()
	wgExtrakey, _ := wgtypes.GenerateKey()

	err = client.ConfigureDevice(testInterface, wgtypes.Config{
		PrivateKey:   &wgPrivkey,
		ListenPort:   &listenPort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			// Peer that will get a handshake
			{
				PublicKey:         wgClientPrivkey.PublicKey(),
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					*ipv4ClientNet,
				},
			},
			// Peer that will not get a handshake
			{
				PublicKey: wgExtrakey,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	err = client.ConfigureDevice(testClientInterface, wgtypes.Config{
		PrivateKey:   &wgClientPrivkey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			// Peer that will connect to the wireguard test interface
			{
				PublicKey:         wgPrivkey.PublicKey(),
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					*ipv4Net,
				},
				Endpoint: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"),
					Port: listenPort},
				PersistentKeepaliveInterval: &keepAliveInterval,
			},
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	// Sleep so that there's time for a handshake between the peers
	time.Sleep(time.Second * 2)

	wg, err := wireguard.New([]string{testInterface}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	t.Run("check connected keys", func(t *testing.T) {
		connectedKeys := wg.UpdatePeers(apiFixture)

		expectedKeys := api.ConnectedKeysMap{
			wgClientPrivkey.PublicKey().String(): 1,
		}

		if diff := cmp.Diff(expectedKeys, connectedKeys); diff != "" {
			t.Fatalf("unexpected keys (-want +got):\n%s", diff)
		}
	})

	t.Run("add peers", func(t *testing.T) {

		wg.UpdatePeers(apiFixture)

		device, err := client.Device(testInterface)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(peerFixture, device.Peers); diff != "" {
			t.Fatalf("unexpected peers (-want +got):\n%s", diff)
		}
	})

	t.Run("update peer ip", func(t *testing.T) {
		apiFixture[0].IPv4 = "10.99.0.2/32"
		apiFixture[0].IPv6 = "fc00:bbbb:bbbb:bb01::2/128"
		wg.UpdatePeers(apiFixture)

		device, err := client.Device(testInterface)
		if err != nil {
			t.Fatal(err)
		}

		peerFixture[0].AllowedIPs[0].IP = net.ParseIP("10.99.0.2")
		peerFixture[0].AllowedIPs[1].IP = net.ParseIP("fc00:bbbb:bbbb:bb01::2")

		if diff := cmp.Diff(peerFixture, device.Peers); diff != "" {
			t.Fatalf("unexpected peers (-want +got):\n%s", diff)
		}
	})

	t.Run("remove peers", func(t *testing.T) {
		wg.UpdatePeers(api.WireguardPeerList{})

		device, err := client.Device(testInterface)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff([]wgtypes.Peer(nil), device.Peers); diff != "" {
			t.Fatalf("unexpected peers (-want +got):\n%s", diff)
		}
	})

	t.Run("add single peer", func(t *testing.T) {
		wg.AddPeer(apiFixture[0])

		device, err := client.Device(testInterface)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(peerFixture, device.Peers); diff != "" {
			t.Fatalf("unexpected peers (-want +got):\n%s", diff)
		}
	})

	t.Run("remove single peer", func(t *testing.T) {
		wg.RemovePeer(apiFixture[0])

		device, err := client.Device(testInterface)
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff([]wgtypes.Peer(nil), device.Peers); diff != "" {
			t.Fatalf("unexpected peers (-want +got):\n%s", diff)
		}
	})
}

func resetDevice(t *testing.T, c *wgctrl.Client) {
	t.Helper()

	cfg := wgtypes.Config{
		ReplacePeers: true,
	}

	if err := c.ConfigureDevice(testInterface, cfg); err != nil {
		t.Fatalf("failed to reset%v", err)
	}
}

func TestInvalidInterface(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests")
	}

	interfaceName := "nonexistant"

	_, err := wireguard.New([]string{interfaceName}, nil)
	if err == nil {
		t.Fatal("no error")
	}
}
