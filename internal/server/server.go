package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Server represents a HTTP(S) proxy
type Server struct {
	router *mux.Router
	http   *http.Server
}

// NewServer returns a new HTTP(S) proxy instance
func NewServer() *Server {
	s := &Server{
		router: mux.NewRouter(),
	}

	h := &http.Server{
		Addr:    ":8080",
		Handler: s,
	}

	s.http = h
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host != "" {
		// Proxy request
		log.WithFields(log.Fields{
			"source": r.RemoteAddr,
			"method": r.Method,
			"url":    r.URL,
		}).Trace("Proxying HTTP request")

		r2, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "Bad request: %v", err)
			return
		}

		r2.Header = r.Header
		r2.Header["X-Forwarded-For"] = []string{strings.Split(r.RemoteAddr, ":")[0]}

		res, err := http.DefaultTransport.RoundTrip(r2)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "Upstream request failed: %v", err)
			return
		}

		header := w.Header()
		for name, value := range res.Header {
			if name == "Proxy-Connection" {
				continue
			}

			header[name] = value
		}
		w.WriteHeader(res.StatusCode)

		defer res.Body.Close()
		if _, err := io.Copy(w, res.Body); err != nil {
			log.WithField("err", err).Error("Failed to proxy request")
		}
	} else {
		// Local request
		s.router.ServeHTTP(w, r)
	}
}
