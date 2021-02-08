package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

// API is a utility for communicating with the Mullvad API
type API struct {
	Username      string
	Password      string
	BaseURL       string
	Hostname      string
	Client        *http.Client
	PeerCachePath string
}

// WireguardPeerList is a list of Wireguard peers
type WireguardPeerList []WireguardPeer

// WireguardPeer is a wireguard peer
type WireguardPeer struct {
	IPv4   string   `json:"ipv4"`
	IPv6   string   `json:"ipv6"`
	Ports  []int    `json:"ports"`
	Cities []string `json:"cities,omitempty"`
	Pubkey string   `json:"pubkey"`
}

// ConnectedKeysMap contains connected keys and their respective number of keys
type ConnectedKeysMap map[string]int

func (a *API) updateWireguardPeerCache() error {
	req, err := http.NewRequest("GET", a.BaseURL+"/internal/active-wireguard-peers/", nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Relay-Hostname", a.Hostname)

	if a.Username != "" && a.Password != "" {
		req.SetBasicAuth(a.Username, a.Password)
	}

	response, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	cache, err := os.Create(a.PeerCachePath)
	if err != nil {
		return err
	}

	_, err = io.Copy(cache, response.Body)

	return err
}

func (a *API) clearWireguardPeerCache() {
	os.Remove(a.PeerCachePath)
}

// GetWireguardPeers fetches a list of wireguard peers from the API and returns it
func (a *API) GetWireguardPeers() (WireguardPeerList, error) {

	// Update the cache.
	err := a.updateWireguardPeerCache()
	if err != nil {
		return WireguardPeerList{}, err
	}
	defer a.clearWireguardPeerCache()

	content, err := ioutil.ReadFile(a.PeerCachePath)
	if err != nil {
		return WireguardPeerList{}, err
	}

	var decodedResponse WireguardPeerList
	err = json.Unmarshal(content, &decodedResponse)
	if err != nil {
		return WireguardPeerList{}, fmt.Errorf("error decoding wireguard peers")
	}

	return decodedResponse, nil
}

// PostWireguardConnections posts the number of connected wireguard keys to the API
func (a *API) PostWireguardConnections(keys ConnectedKeysMap) error {
	connectionsMap := make(map[string]ConnectedKeysMap)
	connectionsMap["connections"] = keys

	buffer := new(bytes.Buffer)
	json.NewEncoder(buffer).Encode(connectionsMap)
	req, err := http.NewRequest("POST", a.BaseURL+"/internal/wireguard-connection-report/", buffer)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-Relay-Hostname", a.Hostname)

	if a.Username != "" && a.Password != "" {
		req.SetBasicAuth(a.Username, a.Password)
	}

	response, err := a.Client.Do(req)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	return nil
}
