package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request) {
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
}
