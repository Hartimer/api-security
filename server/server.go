package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	APIKeyHeader = "X-API-Key"
	HMACHeader   = "X-HMAC"
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
			http.MethodGet,
			"/v1/private",
			s.Private,
		},
		{
			"TamperProof",
			http.MethodGet,
			"/v1/tamperproof",
			s.TamperProof,
		},
		{
			"NonRepudiation",
			http.MethodGet,
			"/v1/nonrepudiation",
			s.NonRepudiation,
		},
	}
}

// Public responds to any request
func (s *Server) Public(w http.ResponseWriter, _ *http.Request) {
	resp := Message{Content: "Hi there to the public"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("Failed to write response: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// Private responds to requests that have a valid API Key
func (s *Server) Private(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	resp := Message{Content: "Hi there in private"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("Failed to write response: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// TamperProof responds to request with a valid API key and HMAC
func (s *Server) TamperProof(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get(APIKeyHeader)
	if err := checkAPIKey(apiKey); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	hmacValue := r.Header.Get(HMACHeader)
	if hmacValue == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	requestHMACResult, err := hex.DecodeString(hmacValue)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hasher := hmac.New(sha256.New, []byte(apiKey))
	if _, err := hasher.Write(bodyBytes); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	hmacResult := hasher.Sum(nil)
	if !bytes.Equal(requestHMACResult, hmacResult) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := Message{Content: "HMACs do not match"}
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			log.Printf("Failed to write response: %+v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	resp := Message{Content: "verified"}
	if err := json.NewEncoder(w).Encode(&resp); err != nil {
		log.Printf("Failed to write response: %+v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// NonRepudiation responds to request with a valid digital signature
func (s *Server) NonRepudiation(w http.ResponseWriter, r *http.Request) {

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
