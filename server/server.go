package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	APIKeyHeader    = "X-API-Key"
	ChecksumHeader  = "X-Checksum"
	HMACHeader      = "X-HMAC"
	SignatureHeader = "X-Signature"
	PublicKeyHeader = "X-Public-Key"
)

// Message is a dummy response type
type Message struct {
	Content string `json:"content"`
}

// Server is the secure API server
type Server struct {
}

// Routes returns the available routes for this server
func (s *Server) Routes() []Route {
	return []Route{
		{
			"Public",
			http.MethodGet,
			"/v1/public",
			s.Public,
		},
		{
			"Private",
			http.MethodPost,
			"/v1/private",
			s.Private,
		},
		{
			"Checksum",
			http.MethodPost,
			"/v1/checksum",
			s.Checksum,
		},
		{
			"TamperProof",
			http.MethodPost,
			"/v1/tamperproof",
			s.TamperProof,
		},
		{
			"NonRepudiation",
			http.MethodPost,
			"/v1/nonrepudiation",
			s.NonRepudiation,
		},
	}
}

// Public responds to any request
//
// Example call:
// curl -sSL -XGET localhost:8080/v1/public
func (s *Server) Public(w http.ResponseWriter, _ *http.Request) {
	resp := Message{Content: "Hi there to the public"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// Private responds to requests that have a valid API Key
//
// Example call:
// curl -sSL -XPOST -H "X-API-Key: MY_KEY" localhost:8080/v1/private
func (s *Server) Private(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp := Message{Content: "Hi there in private"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// Checksum responds to request with a valid API key and SHA256 checksum
//
// Example call:
// export CONTENT="secret"
// export CONTENT_CHECKSUM=$(echo -n "$CONTENT" | sha256sum | cut -d' ' -f 1)
// echo -n "$CONTENT" | curl -sSL -XPOST -H "X-API-Key: MY_KEY" -H "X-Checksum: $CONTENT_CHECKSUM" -d @- "localhost:8080/v1/checksum"
func (s *Server) Checksum(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	checksumValue := r.Header.Get(ChecksumHeader)
	if checksumValue == "" {
		log.Println("missing checksum")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hasher := sha256.New()
	if _, err := hasher.Write(bodyBytes); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	calculatedChecksum := hex.EncodeToString(hasher.Sum(nil))
	if checksumValue != calculatedChecksum {
		log.Println("invalid checksum")
		w.WriteHeader(http.StatusUnauthorized)
		resp := Message{Content: "invalid checksum"}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			log.Printf("%+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	resp := Message{Content: "verified"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// TamperProof responds to request with a valid API key and HMAC
//
// Example call:
// export CONTENT="secret"
// export API_KEY="MY_KEY"
// export CONTENT_HMAC=$(echo -n "$CONTENT" | hmac256 $API_KEY)
// echo -n "$CONTENT" | curl -sSL -XPOST -H "X-API-Key: $API_KEY" -H "X-HMAC: $CONTENT_HMAC" -d @- localhost:8080/v1/tamperproof
func (s *Server) TamperProof(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hmacValue := r.Header.Get(HMACHeader)
	if hmacValue == "" {
		log.Println("missing HMAC")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	requestHMACResult, err := hex.DecodeString(hmacValue)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hasher := hmac.New(sha256.New, []byte(apiKey))
	if _, err := hasher.Write(bodyBytes); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hmacResult := hasher.Sum(nil)
	if !bytes.Equal(requestHMACResult, hmacResult) {
		log.Println("invalid HMAC")
		w.WriteHeader(http.StatusUnauthorized)
		resp := Message{Content: "invalid HMAC"}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			log.Printf("%+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	resp := Message{Content: "verified"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// NonRepudiation responds to request with a valid digital signature
//
// Example call:
// export CONTENT="secret"
// export API_KEY="MY_KEY"
// export PRIVATE_KEY=$(openssl ecparam -genkey -name secp384r1 -noout)
// export PUBLIC_KEY=$(openssl ec -in <(echo "$PRIVATE_KEY") -pubout | head -n -1 | tail -n +2 | base64 -d | xxd -p -c 256)
// export SIGNATURE=$(echo -n $CONTENT | sha256sum - | cut -d' ' -f 1 | xxd -r -p | openssl pkeyutl -sign -inkey <(echo "$PRIVATE_KEY") | xxd -p -c 256)
// echo -n "$CONTENT" | curl -sSL -XPOST -H "X-API-Key: $API_KEY" -H "X-Public-Key: $PUBLIC_KEY" -H "X-Signature: $SIGNATURE" -d @- localhost:8080/v1/nonrepudiation
func (s *Server) NonRepudiation(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	signature := r.Header.Get(SignatureHeader)
	if signature == "" {
		log.Println("signature missing")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	publicKey := r.Header.Get(PublicKeyHeader)
	if publicKey == "" {
		log.Println("public key missing")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	publicKeyBase64 := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, base64.StdEncoding.EncodeToString(publicKeyBytes))

	block, _ := pem.Decode([]byte(publicKeyBase64))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	pubKey := pub.(*ecdsa.PublicKey)
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	hasher := sha256.New()
	_, err = hasher.Write(bodyBytes)
	if err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ecdsa.VerifyASN1(pubKey, hasher.Sum(nil), signatureBytes) {
		log.Printf("invalid signature: %x, %x, %s", publicKeyBytes, signatureBytes, string(bodyBytes))
		w.WriteHeader(http.StatusUnauthorized)
		resp := Message{Content: "invalid signature"}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			log.Printf("%+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	resp := Message{Content: "verified"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("%+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// checkAPIKey validates the API Key.
// For the sake of this example, any non-empty, all-uppercase key is valid
func checkAPIKey(apiKey string) error {
	if apiKey == "" {
		return fmt.Errorf("API Key is missing")
	}
	if strings.ToUpper(apiKey) != apiKey {
		return fmt.Errorf("invalid API Key")
	}
	return nil
}
