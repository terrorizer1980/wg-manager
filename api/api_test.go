package api_test

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"strings"

	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mullvad/wg-manager/api"
)

var peerFixture = api.WireguardPeerList{
	api.WireguardPeer{
		IPv4:   "10.99.0.1/32",
		IPv6:   "fc00:bbbb:bbbb:bb01::1/128",
		Ports:  []int{1234, 4321},
		Pubkey: strings.Repeat("a", 44),
	},
}

var connectedKeysFixture = api.ConnectedKeysMap{
	strings.Repeat("a", 32): 1,
	strings.Repeat("b", 32): 2,
}

func TestGetWireguardPeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		bytes, _ := json.Marshal(peerFixture)
		rw.Write(bytes)
	}))
	// Close the server when test finishes
	defer server.Close()

	// Use Client & URL from our local test server
	api := api.API{
		BaseURL:  server.URL,
		Client:   server.Client(),
		Username: "foo",
		Password: "bar",
		Hostname: "test",
	}

	peers, err := api.GetWireguardPeers()
	if err != nil {
		t.Fatalf(err.Error())
	}

	if !reflect.DeepEqual(peers, peerFixture) {
		t.Errorf("got unexpected result, wanted %+v, got %+v", peers, peerFixture)
	}
}

func TestPostWireguardPeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Fatalf(err.Error())
		}

		var connectedKeys api.ConnectedKeysMap
		err = json.Unmarshal(body, &connectedKeys)
		if err != nil {
			t.Fatalf(err.Error())
		}

		if !reflect.DeepEqual(connectedKeys, connectedKeysFixture) {
			t.Errorf("got unexpected result, wanted %+v, got %+v", connectedKeys, connectedKeysFixture)
		}

		rw.WriteHeader(http.StatusOK)
	}))
	// Close the server when test finishes
	defer server.Close()

	// Use Client & URL from our local test server
	a := api.API{
		BaseURL:  server.URL,
		Client:   server.Client(),
		Username: "foo",
		Password: "bar",
		Hostname: "test",
	}

	// Create a copy so that we don't alter the fixture
	connectedKeysCopy := make(api.ConnectedKeysMap)

	for k, v := range connectedKeysFixture {
		connectedKeysCopy[k] = v
	}

	err := a.PostWireguardConnections(connectedKeysCopy)
	if err != nil {
		t.Fatalf(err.Error())
	}
}
