package main

import (
	"apisecurity/server"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	s := &server.Server{}
	router := mux.NewRouter().StrictSlash(true)
	for _, route := range s.Routes() {
		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(route.HandlerFunc)
	}

	httpServer := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           router,
	}
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on port %s. Press CTRL+C to stop", port)
	if err := httpServer.Serve(listener); err != nil {
		log.Fatal(err)
	}
}
