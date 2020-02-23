package server

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Server represents a HTTP(S) proxy
type Server struct {
	http *http.Server
}

// NewServer returns a new HTTP(S) proxy instance
func NewServer() *Server {
	r := mux.NewRouter()
	h := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	s := &Server{
		h,
	}
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello, world!\n")
	})

	return s
}

// Start begins the HTTP proxy listening
func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

// Stop shuts down the HTTP server
func (s *Server) Stop() error {
	return s.http.Close()
}
