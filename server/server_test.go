package server_test

import (
	"apisecurity/server"
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

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "missing")

	// When we request private endpoint with an invalid key
	req, err = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "lowercase_key")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "invalid")

	// When we request private endpoint with an valid key
	req, err = http.NewRequest(http.MethodGet, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "UPPERCASE_KEY")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "private")
}
