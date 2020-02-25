package server

import (
	"net/http"

	"github.com/r3labs/sse"

	"github.com/gorilla/mux"
)

// Server represents a HTTP(S) proxy
type Server struct {
	router *mux.Router
	http   *http.Server
	cache  *Cache
	events *sse.Server
}

// NewServer returns a new HTTP(S) proxy instance
func NewServer(cachePath string) (*Server, error) {
	c, err := NewCache(cachePath)
	if err != nil {
		return nil, err
	}

	s := &Server{
		router: mux.NewRouter(),
		cache:  c,
	}
	s.mountConsole()

	h := &http.Server{
		Addr:    ":8080",
		Handler: s,
	}

	s.http = h
	return s, nil
}

// Start begins the HTTP proxy listening
func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

// Stop shuts down the HTTP server
func (s *Server) Stop() error {
	return s.http.Close()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// Proxy CONNECT request (e.g. HTTPS, WebSocket)
		s.proxyCONNECT(w, r)
	} else if r.URL.Host != "" {
		// Proxy HTTP request
		s.proxyHTTP(w, r)
	} else {
		// Local request
		s.router.ServeHTTP(w, r)
	}
}
