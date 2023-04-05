package server_test

import (
	"apisecurity/server"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// When we request private endpoint with an invalid key
	req, err = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "lowercase_key")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// When we request private endpoint with an valid key
	req, err = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/private", nil)
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, "UPPERCASE_KEY")
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestChecksum(t *testing.T) {
	// Given a server
	httpServer := initiateServer()
	defer httpServer.Close()
	apiKey := "UPPERCASE_KEY"
	message := []byte("secret")

	// When we request checksum endpoint with valid hash
	hasher := sha256.New()
	_, err := hasher.Write(message)
	require.NoError(t, err)
	checksum := hasher.Sum(nil)
	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/checksum", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.ChecksumHeader, hex.EncodeToString(checksum))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it succeeds
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "verified")

	// When we request checksum endpoint with invalid hash
	hasher = sha256.New()
	_, err = hasher.Write(message)
	require.NoError(t, err)
	_, err = hasher.Write([]byte("MORE_FAKE_DATA"))
	require.NoError(t, err)
	checksum = hasher.Sum(nil)
	req, err = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/checksum", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.ChecksumHeader, hex.EncodeToString(checksum))
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "invalid checksum")
}

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
	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/tamperproof", bytes.NewReader(message))
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
	req, err = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/tamperproof", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.HMACHeader, hex.EncodeToString(hashedMessage))
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)

	// Then it fails
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "invalid HMAC")
}

func TestNonRepudiation(t *testing.T) {
	// Given a server
	httpServer := initiateServer()
	defer httpServer.Close()
	apiKey := "UPPERCASE_KEY"
	message := []byte("secret")
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// When we request nonrepudiation endpoint with valid signature
	signature, publicKey, err := sign(t, privateKey, message)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/nonrepudiation", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.SignatureHeader, signature)
	req.Header.Add(server.PublicKeyHeader, publicKey)
	resp, err := http.DefaultClient.Do(req)

	// Then it succeeds
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "verified")

	// Given a different key
	privateKey2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// When we request with message signed with a different key
	signature, _, err = sign(t, privateKey2, message)
	require.NoError(t, err)
	req, err = http.NewRequest(http.MethodPost, httpServer.URL+"/v1/nonrepudiation", bytes.NewReader(message))
	require.NoError(t, err)
	req.Header.Add(server.APIKeyHeader, apiKey)
	req.Header.Add(server.SignatureHeader, signature)
	req.Header.Add(server.PublicKeyHeader, publicKey)
	resp, err = http.DefaultClient.Do(req)

	// Then it fails
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// And we get expected message
	defer resp.Body.Close()
	bodyBytes, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(bodyBytes), "invalid signature")
}

// sign signs the provided payload using the given key, and returns both the hex encoded signature
// and the hex encoded PEM exported public key.
func sign(t *testing.T, privateKey *ecdsa.PrivateKey, payload []byte) (string, string, error) {
	t.Helper()

	hasher := sha256.New()
	if _, err := hasher.Write(payload); err != nil {
		return "", "", err
	}
	signatureBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hasher.Sum(nil))
	if err != nil {
		return "", "", err
	}

	// We need to marshal the public key in PEM format and convert it to hex
	pkixBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	}
	var pemBuffer bytes.Buffer
	require.NoError(t, pem.Encode(&pemBuffer, block))
	parts := strings.Split(pemBuffer.String(), "\n")
	parts = parts[1 : len(parts)-2]
	publicKeyBytes, err := base64.StdEncoding.DecodeString(strings.Join(parts, ""))
	if err != nil {
		return "", "", err
	}

	return hex.EncodeToString(signatureBytes), hex.EncodeToString(publicKeyBytes), nil
}
