package server

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Cache represents an HTTP cache
type Cache struct {
	Path string
}

// NewCache creates a new HTTP cache
func NewCache(path string) (*Cache, error) {
	if path == "" {
		return &Cache{""}, nil
	}

	log.Info("Enabling cache")
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}

	return &Cache{path}, nil
}

func hashString(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}
func (c *Cache) keyedPath(r *http.Response) (string, error) {
	parent := path.Join(c.Path, hashString(r.Request.Host), hashString(r.Request.URL.RequestURI()))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create cache entry parent directories: %w", err)
	}

	file := "base"
	if vary, ok := r.Header["Vary"]; ok {
		var sorted []string
		var values []string
		for _, header := range strings.Split(vary[0], ",") {
			header = strings.TrimSpace(header)
			header = http.CanonicalHeaderKey(header)
			if _, ok := r.Request.Header[header]; !ok {
				r.Request.Header[header] = []string{""}
			}

			sorted = append(sorted, header)
		}
		sort.Strings(sorted)
		for _, header := range sorted {
			sort.Strings(r.Request.Header[header])
			valueEnc, _ := json.Marshal(r.Request.Header[header])
			values = append(values, string(valueEnc))
		}

		key := strings.Join(sorted, ",")
		value := strings.Join(values, ",")
		log.WithFields(log.Fields{
			"file":  file,
			"key":   key,
			"value": value,
		}).Trace("Varying with SHA256 value")
		file = fmt.Sprintf("%v_%v", key, hashString(value))
	}
	return filepath.Join(parent, file), nil
}

// Store transparently handles caching a HTTP response
func (c *Cache) Store(r *http.Response) (io.ReadCloser, error) {
	if c.Path == "" || r.Request.Method != http.MethodGet || r.StatusCode != http.StatusOK {
		// We will only cache GET requests with a 200 response
		return r.Body, nil
	}
	if vary, ok := r.Header["Vary"]; ok && strings.TrimSpace(vary[0]) == "*" {
		return r.Body, nil
	}

	authOk := false
	if controls, ok := r.Header["Cache-Control"]; ok {
		for _, control := range controls {
			if i := strings.Index(control, "="); i != -1 {
				control = control[:i]
			}
			control = strings.ToLower(control)

			switch control {
			case "no-store", "private":
				return r.Body, nil
			case "public", "must-revalidate", "s-maxage":
				authOk = true
			}
		}
	}

	if _, ok := r.Header["Authorization"]; ok && !authOk {
		return r.Body, nil
	}

	defer r.Body.Close()
	path, err := c.keyedPath(r)
	if err != nil {
		return nil, err
	}

	log.WithField("path", path).Trace("Storing request")
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to create cache entry: %w", err)
	}

	if err := json.NewEncoder(f).Encode(r.Header); err != nil {
		return nil, fmt.Errorf("Failed to write headers to cache entry: %w", err)
	}
	bodyStart, err := f.Seek(0, os.SEEK_CUR)
	if err != nil {
		return nil, fmt.Errorf("Failed to get cache entry file positiob: %w", err)
	}

	if _, err := io.Copy(f, r.Body); err != nil {
		return nil, fmt.Errorf("Failed to write destination response to cache entry: %w", err)
	}

	if _, err := f.Seek(bodyStart, os.SEEK_SET); err != nil {
		return nil, fmt.Errorf("Failed to rewind cache entry: %w", err)
	}
	return f, nil
}

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
	delete(r2.Header, "Proxy-Connection")
	r2.Header["X-Forwarded-For"] = []string{strings.Split(r.RemoteAddr, ":")[0]}

	res, err := http.DefaultTransport.RoundTrip(r2)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "Upstream request failed: %v", err)
		return
	}

	resHeader := w.Header()
	for name, value := range res.Header {
		resHeader[name] = value
	}

	rr, err := s.cache.Store(res)
	if err != nil {
		log.WithField("err", err).Error("Failed to store cache entry")
		http.Error(w, "Cache write failed", http.StatusInternalServerError)
		return
	}
	defer rr.Close()

	w.WriteHeader(res.StatusCode)
	if _, err := io.Copy(w, rr); err != nil {
		log.WithField("err", err).Error("Failed to proxy request")
	}
}
