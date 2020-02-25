package server

import (
	"bufio"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

var entryRegex = regexp.MustCompile(`^(\S+)_(\S+)$`)

// calculateVaryKey calculates a unique, stable (ordering of headers doesn't matter) filename based on a Vary header
// and the values of the given headers in the request
func calculateVaryKey(vary string, r *http.Request) string {
	var sorted []string
	var values []string
	for _, header := range strings.Split(vary, ",") {
		header = strings.TrimSpace(header)
		header = http.CanonicalHeaderKey(header)
		if _, ok := r.Header[header]; !ok {
			r.Header[header] = []string{""}
		}

		sorted = append(sorted, header)
	}

	// Sort to make the key stable (order of headers might vary)
	sort.Strings(sorted)
	for _, header := range sorted {
		sort.Strings(r.Header[header])
		valueEnc, _ := json.Marshal(r.Header[header])
		values = append(values, string(valueEnc))
	}

	// TODO: List of headers could be quite long, might exceed max file length - store in a "database" in the dir
	key := strings.Join(sorted, ",")
	value := strings.Join(values, ",")
	log.WithFields(log.Fields{
		"key":   key,
		"value": value,
	}).Debug("Unencoded Vary key")
	return fmt.Sprintf("%v_%v", key, hashString(value))
}
func (c *Cache) keyedPath(vary string, r *http.Request) (string, error) {
	parent := path.Join(c.Path, hashString(r.Host), hashString(r.URL.RequestURI()))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("Failed to create cache entry parent directories: %w", err)
	}

	file := "base"

	if vary != "" {
		// We have the Vary header (i.e. we have response), we can calculate the required key
		file = calculateVaryKey(vary, r)
	} else {
		// Either no response or response doesn't contain Vary header - let's try to find a suitable existing candidate
		files, err := ioutil.ReadDir(parent)
		if err != nil {
			return "", fmt.Errorf("Failed to list files in cache directory: %w", err)
		}

		var candidates []os.FileInfo
		for _, info := range files {
			// Only want to look at existing varied requests
			m := entryRegex.FindStringSubmatch(info.Name())
			if len(m) == 0 {
				continue
			}

			if calculateVaryKey(m[1], r) == info.Name() {
				log.WithField("key", info.Name()).Debug("Found existing cached request matching Vary requirements")
				candidates = append(candidates, info)
			}
		}

		if len(candidates) != 0 {
			// Use newest matching response
			sort.Slice(candidates, func(i, j int) bool {
				return candidates[i].ModTime().After(files[j].ModTime())
			})

			file = candidates[0].Name()
		}
	}

	return filepath.Join(parent, file), nil
}

// Store transparently handles caching a HTTP response
func (c *Cache) Store(r *http.Response) error {
	if c.Path == "" || r.Request.Method != http.MethodGet || r.StatusCode != http.StatusOK {
		// We will only cache GET requests with a 200 response
		return nil
	}
	if vary, ok := r.Header["Vary"]; ok && strings.TrimSpace(vary[0]) == "*" {
		return nil
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
				return nil
			case "public", "must-revalidate", "s-maxage":
				authOk = true
			}
		}
	}

	if _, ok := r.Header["Authorization"]; ok && !authOk {
		return nil
	}

	defer r.Body.Close()
	vary := ""
	if v, ok := r.Header["Vary"]; ok {
		vary = v[0]
	}
	path, err := c.keyedPath(vary, r.Request)
	if err != nil {
		return err
	}

	log.WithField("path", path).Trace("Storing request")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to create cache entry: %w", err)
	}

	if err := r.Write(f); err != nil {
		return fmt.Errorf("Failed to write HTTP response out to cache: %w", err)
	}
	if _, err := f.Seek(0, os.SEEK_SET); err != nil {
		return fmt.Errorf("Failed to rewind cache entry: %w", err)
	}

	cacheRes, err := http.ReadResponse(bufio.NewReader(f), r.Request)
	if err != nil {
		return fmt.Errorf("Failed to parse on-disk cache entry: %w", err)
	}

	*r = *cacheRes
	return nil
}

func errRes(s int) *http.Response {
	return &http.Response{StatusCode: s}
}
func (c *Cache) doReq(r *http.Request) error {
	r2, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		r.Response = errRes(http.StatusBadRequest)
		return fmt.Errorf("Bad request: %w", err)
	}

	r2.Header = r.Header
	r2.Header["X-Forwarded-For"] = []string{strings.Split(r.RemoteAddr, ":")[0]}

	res, err := http.DefaultTransport.RoundTrip(r2)
	if err != nil {
		r.Response = errRes(http.StatusBadGateway)
		return fmt.Errorf("Backend request failed: %w", err)
	}

	if err = c.Store(res); err != nil {
		r.Response = errRes(http.StatusInternalServerError)
		return err
	}
	r.Response = res
	return nil
}
func validateStored(r *http.Response) error {
	return nil
}

// Load transparently attempts to retrieve a HTTP response from cache, connecting to the backend as necessary
func (c *Cache) Load(r *http.Request) error {
	if c.Path == "" {
		return c.doReq(r)
	}

	path, err := c.keyedPath("", r)
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.Response = errRes(http.StatusInternalServerError)
			return fmt.Errorf("Failed to open cache entry for reading: %w", err)
		}

		return c.doReq(r)
	}

	log.WithField("path", path).Trace("Attempting to use stored request")

	res, err := http.ReadResponse(bufio.NewReader(f), r)
	if err != nil {
		f.Close()
		r.Response = errRes(http.StatusInternalServerError)
		return fmt.Errorf("Failed to parse on-disk cache entry: %w", err)
	}

	r.Response = res
	return nil
}

func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"source": r.RemoteAddr,
		"method": r.Method,
		"url":    r.URL,
	}).Trace("Proxying HTTP request")

	if err := s.cache.Load(r); err != nil {
		log.WithField("err", err).Error("Failed to proxy HTTP request")
		http.Error(w, err.Error(), r.Response.StatusCode)
		return
	}
	defer r.Response.Body.Close()

	resHeader := w.Header()
	for name, value := range r.Response.Header {
		resHeader[name] = value
	}
	w.WriteHeader(r.Response.StatusCode)
	if _, err := io.Copy(w, r.Response.Body); err != nil {
		log.WithField("err", err).Error("Failed to send proxied HTTP response")
	}
}
