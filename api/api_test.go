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
		Cities: []string{"se-mma", "se-got"},
		Pubkey: strings.Repeat("a", 44),
	},
}

var peerWithoutCitiesFixtures = api.WireguardPeerList{
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

var connectionsFixture = map[string]api.ConnectedKeysMap{
	"connections": connectedKeysFixture,
}

// More a sanity check than anything else to know what a null element in the json struct unmarshals to.
func TestWireGuardPeerWithNullElements(t *testing.T) {
	json_data := `[{"ipv4":"10.99.0.1/32","ipv6":"fc00:bbbb:bbbb:bb01::1/128","ports":[1234,4321],"cities":[null,"se-got"],"pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`
	var decodedResponse api.WireguardPeerList
	json.Unmarshal([]byte(json_data), &decodedResponse)
	if decodedResponse[0].Cities[0] != "" {
		t.Fatalf("null json element not converted to empty string")
	}
}

func TestGetWireguardPeers(t *testing.T) {
	call_count := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Return different responses depending on call number.
		switch call_count {
		case 0:
			call_count += 1
			bytes, _ := json.Marshal(peerFixture)
			rw.Write(bytes)
		case 1:
			call_count += 1
			bytes, _ := json.Marshal(peerWithoutCitiesFixtures)
			rw.Write(bytes)
		}
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

	// First get peers from the api with cities present.
	peers, err := api.GetWireguardPeers()
	if err != nil {
		t.Fatalf(err.Error())
	}

	if !reflect.DeepEqual(peers, peerFixture) {
		t.Errorf("got unexpected result, wanted %+v, got %+v", peers, peerFixture)
	}

	// Secondly get peers from the api without cities present.
	peers, err = api.GetWireguardPeers()
	if err != nil {
		t.Fatalf(err.Error())
	}

	if len(peers[0].Cities) != 0 {
		t.Errorf("Cities list not empty")
	}

	if !reflect.DeepEqual(peers, peerWithoutCitiesFixtures) {
		t.Errorf("got unexpected result, wanted %+v, got %+v", peers, peerFixture)
	}

}

func TestPostWireguardPeers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			t.Fatalf(err.Error())
		}

		var connectedKeys map[string]api.ConnectedKeysMap
		err = json.Unmarshal(body, &connectedKeys)
		if err != nil {
			t.Fatalf(err.Error())
		}

		if !reflect.DeepEqual(connectedKeys, connectionsFixture) {
			t.Errorf("got unexpected result, wanted %+v, got %+v", connectedKeys, connectionsFixture)
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
