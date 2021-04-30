package wireguard

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/infosum/statsd"
	"github.com/mullvad/wg-manager/api"

	"github.com/mullvad/wg-manager/iputil"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Wireguard is a utility for managing wireguard configuration
type Wireguard struct {
	client     *wgctrl.Client
	interfaces []string
	metrics    *statsd.Client
}

// New ensures that the interfaces given are valid, and returns a new Wireguard instance
func New(interfaces []string, metrics *statsd.Client) (*Wireguard, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		_, err := client.Device(i)
		if err != nil {
			return nil, fmt.Errorf("error getting wireguard interface %s: %s", i, err.Error())
		}
	}

	return &Wireguard{
		client:     client,
		interfaces: interfaces,
		metrics:    metrics,
	}, nil
}

func (w *Wireguard) ResetPeers() {
	for _, d := range w.interfaces {
		removePeers := []wgtypes.PeerConfig{}
		addPeers := []wgtypes.PeerConfig{}
		dev, err := w.client.Device(d)
		if err != nil {
			// TODO: Add some kind of useful error message
			continue
		}
		peers := dev.Peers
		for _, peer := range peers {
			if needsReset(peer) {
				// Remove peers that's previously been active and should be reset to remove data
				removePeers = append(removePeers, wgtypes.PeerConfig{
					PublicKey: peer.PublicKey,
					Remove:    true,
				})

				// Copy the preshared key if one is set
				var emptyKey wgtypes.Key
				var copiedKey wgtypes.Key
				// TODO: Can we just get rid of presharedkey handling alltogether?
				if peer.PresharedKey != emptyKey {
					// TODO: Is this still the case? Perhaps it's now fixed upstream?
					// We need to copy the key, or the pointer gets corrupted for some reason
					copy(copiedKey[:], peer.PresharedKey[:])
				}

				addPeers = append(addPeers, wgtypes.PeerConfig{
					PublicKey:         peer.PublicKey,
					ReplaceAllowedIPs: true,
					PresharedKey:      &copiedKey,
					AllowedIPs:        peer.AllowedIPs,
				})
			}
		}
		// No changes needed
		if len(removePeers) == 0 {
			continue
		}

		// Add new peers, remove deleted peers, and remove peers should be reset
		err = w.client.ConfigureDevice(d, wgtypes.Config{
			Peers: removePeers,
		})

		if err != nil {
			log.Printf("error configuring wireguard interface %s: %s", d, err.Error())
			continue
		}

		// Re-add the peers we removed to reset in the previous step
		err = w.client.ConfigureDevice(d, wgtypes.Config{
			Peers: addPeers,
		})

		if err != nil {
			log.Printf("error configuring wireguard interface %s: %s", d, err.Error())
			continue
		}
	}
}

func (w *Wireguard) CountPeers() (connectedKeyList api.ConnectedKeysMap) {
	var peerCount, devicePeerCount int
	connectedKeysMap := make(api.ConnectedKeysMap)
	for _, d := range w.interfaces {
		var deviceConnectedKeys []string

		device, err := w.client.Device(d)
		// Log an error, but move on, so that one broken wireguard interface doesn't prevent us from configuring the rest
		if err != nil {
			log.Printf("error connecting to wireguard interface %s: %s", d, err.Error())
			continue
		}

		devicePeerCount, deviceConnectedKeys = countConnectedPeers(device.Peers)
		peerCount += devicePeerCount

		for _, deviceKey := range deviceConnectedKeys {
			if _, ok := connectedKeysMap[deviceKey]; !ok {
				connectedKeysMap[deviceKey] = 1
			} else {
				// If the key already exists, count as another connection
				connectedKeysMap[deviceKey] = connectedKeysMap[deviceKey] + 1
			}
		}

	}

	// Send metrics
	w.metrics.Gauge("connected_peers", peerCount)
	return connectedKeysMap
}

// UpdatePeers updates the configuration of the wireguard interfaces to match the given list of peers
func (w *Wireguard) UpdatePeers(peers api.WireguardPeerList) (connectedKeyList api.ConnectedKeysMap) {
	peerMap := w.mapPeers(peers)

	var peerCount, devicePeerCount int
	connectedKeysMap := make(api.ConnectedKeysMap)
	for _, d := range w.interfaces {
		var deviceConnectedKeys []string

		device, err := w.client.Device(d)
		// Log an error, but move on, so that one broken wireguard interface doesn't prevent us from configuring the rest
		if err != nil {
			log.Printf("error connecting to wireguard interface %s: %s", d, err.Error())
			continue
		}

		devicePeerCount, deviceConnectedKeys = countConnectedPeers(device.Peers)
		peerCount += devicePeerCount

		for _, deviceKey := range deviceConnectedKeys {
			if _, ok := connectedKeysMap[deviceKey]; !ok {
				connectedKeysMap[deviceKey] = 1
			} else {
				// If the key already exists, count as another connection
				connectedKeysMap[deviceKey] = connectedKeysMap[deviceKey] + 1
			}
		}

		existingPeerMap := mapExistingPeers(device.Peers)
		cfgPeers := []wgtypes.PeerConfig{}

		// Loop through peers from the API
		// Add peers not currently existing in the wireguard config
		// Update peers that exist in the wireguard config but has changed
		for key, allowedIPs := range peerMap {
			existingPeer, ok := existingPeerMap[key]
			if !ok || !iputil.EqualIPNet(allowedIPs, existingPeer.AllowedIPs) {
				cfgPeers = append(cfgPeers, wgtypes.PeerConfig{
					PublicKey:         key,
					ReplaceAllowedIPs: true,
					AllowedIPs:        allowedIPs,
				})
			}
		}

		// Loop through the current peers in the wireguard config
		for key := range existingPeerMap {
			if _, ok := peerMap[key]; !ok {
				// Remove peers that doesn't exist in the API
				cfgPeers = append(cfgPeers, wgtypes.PeerConfig{
					PublicKey: key,
					Remove:    true,
				})
			}
		}

		// No changes needed
		if len(cfgPeers) == 0 {
			continue
		}

		// Add new peers, remove deleted peers, and remove peers should be reset
		err = w.client.ConfigureDevice(d, wgtypes.Config{
			Peers: cfgPeers,
		})

		if err != nil {
			log.Printf("error configuring wireguard interface %s: %s", d, err.Error())
			continue
		}

	}

	// Send metrics
	w.metrics.Gauge("connected_peers", peerCount)
	return connectedKeysMap
}

// Take the wireguard peers and convert them into a map for easier comparison
func (w *Wireguard) mapPeers(peers api.WireguardPeerList) (peerMap map[wgtypes.Key][]net.IPNet) {
	peerMap = make(map[wgtypes.Key][]net.IPNet)

	// Ignore peers with errors, in-case we get bad data from the API
	for _, peer := range peers {
		key, ipv4, ipv6, err := parsePeer(peer)
		if err != nil {
			continue
		}

		peerMap[key] = []net.IPNet{
			*ipv4,
			*ipv6,
		}
	}

	return
}

// Take the existing wireguard peers and convert them into a map for easier comparison
func mapExistingPeers(peers []wgtypes.Peer) (peerMap map[wgtypes.Key]wgtypes.Peer) {
	peerMap = make(map[wgtypes.Key]wgtypes.Peer)

	for _, peer := range peers {
		peerMap[peer.PublicKey] = peer
	}

	return
}

// Wireguard sends a handshake roughly every 2 minutes
// So we consider all peers with a handshake within that interval to be connected
const handshakeInterval = time.Minute * 2

// How long since a handshake to consider the peer as connected
const connectedInterval = time.Minute * 3

// Count the connected wireguard peers
func countConnectedPeers(peers []wgtypes.Peer) (devicePeerCount int, deviceConnectedKeys []string) {
	for _, peer := range peers {
		lastHandShakeTime := time.Since(peer.LastHandshakeTime)
		if lastHandShakeTime <= handshakeInterval {
			devicePeerCount++
		}
		if lastHandShakeTime <= connectedInterval {
			deviceConnectedKeys = append(deviceConnectedKeys, peer.PublicKey.String())
		}
	}

	return devicePeerCount, deviceConnectedKeys
}

// A wireguard session can't last for longer then 3 minutes
const inactivityTime = time.Minute * 3

// Whether a peer should be reset or not, to zero out last handshake/bandwidth information
func needsReset(peer wgtypes.Peer) bool {
	if !peer.LastHandshakeTime.IsZero() && time.Since(peer.LastHandshakeTime) > inactivityTime {
		return true
	}

	return false
}

// AddPeer adds the given peer to the wireguard interfaces, without checking the existing configuration
func (w *Wireguard) AddPeer(peer api.WireguardPeer) {
	key, ipv4, ipv6, err := parsePeer(peer)
	if err != nil {
		return
	}

	for _, d := range w.interfaces {
		// Add the peer
		err := w.client.ConfigureDevice(d, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:         key,
					ReplaceAllowedIPs: true,
					AllowedIPs: []net.IPNet{
						*ipv4,
						*ipv6,
					},
				},
			},
		})

		if err != nil {
			log.Printf("error configuring wireguard interface %s: %s", d, err.Error())
			continue
		}
	}
}

// RemovePeer removes the given peer from the wireguard interfaces, without checking the existing configuration
func (w *Wireguard) RemovePeer(peer api.WireguardPeer) {
	key, _, _, err := parsePeer(peer)
	if err != nil {
		return
	}

	for _, d := range w.interfaces {
		// Remove the peer
		err := w.client.ConfigureDevice(d, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: key,
					Remove:    true,
				},
			},
		})

		if err != nil {
			log.Printf("error configuring wireguard interface %s: %s", d, err.Error())
			continue
		}
	}
}

func parsePeer(peer api.WireguardPeer) (key wgtypes.Key, ipv4 *net.IPNet, ipv6 *net.IPNet, err error) {
	key, err = wgtypes.ParseKey(peer.Pubkey)
	if err != nil {
		return
	}

	_, ipv4, err = net.ParseCIDR(peer.IPv4)
	if err != nil {
		return
	}

	_, ipv6, err = net.ParseCIDR(peer.IPv6)
	if err != nil {
		return
	}

	return
}

// Close closes the underlying wireguard client
func (w *Wireguard) Close() {
	w.client.Close()
}
