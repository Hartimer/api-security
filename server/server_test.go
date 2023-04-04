package server_test

import (
	"apisecurity/server"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func initiateServer() *httptest.Server {
	s := &server.Server{}
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range s.Routes() {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	return httptest.NewServer(router)
}

func TestPublic(t *testing.T) {
	// Given a server
	httpServer := initiateServer()
	defer httpServer.Close()

	// When we request public endpoint
	req, err := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/public", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it succeeds
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "public")
}

func TestPrivate(t *testing.T) {
	// Given a server
	httpServer := initiateServer()
	defer httpServer.Close()

	// When we request private endpoint without a key
	req, err := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// When we request private endpoint with an invalid key
	req, err = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "lowercase_key")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// When we request private endpoint with an valid key
	req, err = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "UPPERCASE_KEY")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// From shell
//
// export CONTENT="secret"
// export API_KEY="AAA"
// export CONTENT_HMAC=$(echo -n "$CONTENT" | hmac256 $API_KEY)
// echo -n "$CONTENT" | curl -sSL -XGET -H "X-API-Key: $API_KEY" -H "X-HMAC: $CONTENT_HMAC" -d @- "localhost:8080/v1/tamperproof"
func TestTamperProof(t *testing.T) {
	// Given a server
	httpServer := initiateServer()
	defer httpServer.Close()
	apiKey := "UPPERCASE_KEY"
	message := []byte("secret")

	// When we request tamperproof endpoint with valid HMAC
	hasher := hmac.New(sha256.New, []byte(apiKey))
	_, err := hasher.Write(message)
	require.NoError(t, err)
	hashedMessage := hasher.Sum(nil)
	req, err := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/tamperproof", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.HMACHeader, hex.EncodeToString(hashedMessage))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it succeeds
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "verified")

	// When we request tamperproof endpoint with invalid HMAC
	hasher = hmac.New(sha256.New, []byte(apiKey+"WRONG"))
	_, err = hasher.Write(message)
	require.NoError(t, err)
	hashedMessage = hasher.Sum(nil)
	req, err = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/tamperproof", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.HMACHeader, hex.EncodeToString(hashedMessage))
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
