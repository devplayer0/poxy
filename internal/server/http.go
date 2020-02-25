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
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Cache represents an HTTP cache based on RFC 7234 (https://tools.ietf.org/html/rfc7234)
// Varying requests and serving fresh responses are (mostly) implemented
// Validation of stale requests is unimplemented
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
// https://tools.ietf.org/id/draft-ietf-httpbis-cache-01.html#caching.negotiated.responses
func calculateVaryKey(vary string, r *http.Request) string {
	var sorted []string
	var values []string
	for _, header := range strings.Split(vary, ",") {
		header = strings.TrimSpace(header)
		header = http.CanonicalHeaderKey(header)
		if _, ok := r.Header[header]; !ok {
			// Non-present headers should still be recorded
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
	// It can't be hashed like the value since we need to decode it later
	key := strings.Join(sorted, ",")
	value := strings.Join(values, ",")
	log.WithFields(log.Fields{
		"key":   key,
		"value": value,
	}).Debug("Unencoded Vary key")

	// Hash the value since it might be quite long
	return fmt.Sprintf("%v_%v", key, hashString(value))
}

// keyedPath uses the request Host, URI and Vary response header to calculate a unique key
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

			// The current request generated the same Vary key as a stored reponse
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
// https://tools.ietf.org/id/draft-ietf-httpbis-cache-01.html#response.cacheability
func (c *Cache) Store(r *http.Response) error {
	if c.Path == "" || r.Request.Method != http.MethodGet || r.StatusCode != http.StatusOK {
		// If path is empty, caching is disabled
		// We will only cache GET requests with a 200 response
		return nil
	}
	if vary, ok := r.Header["Vary"]; ok && strings.TrimSpace(vary[0]) == "*" {
		// Vary: * means we should never store the request
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
				// If we're explicitly asked not to store requests, we shouldn't
				return nil
			case "public", "must-revalidate", "s-maxage":
				// Given these values, we are allowed to store requests with an Authorization header
				authOk = true
			}
		}
	}

	if _, ok := r.Header["Authorization"]; ok && !authOk {
		// Unless allowed, we shouldn't store requests with an Authorization header
		return nil
	}

	defer r.Body.Close()
	vary := ""
	if v, ok := r.Header["Vary"]; ok {
		vary = v[0]
	}
	// Calculate the complete key path based on the hostname, request URI and Vary header
	path, err := c.keyedPath(vary, r.Request)
	if err != nil {
		return err
	}

	// We're allowed store the response, so let's create a new file to store it in (or overwrite an existing one)
	log.WithField("path", path).Trace("Storing request")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("Failed to create cache entry: %w", err)
	}

	// Write the response from upstream to the cache
	if err := r.Write(f); err != nil {
		return fmt.Errorf("Failed to write HTTP response out to cache: %w", err)
	}
	// Rewind so the response can be parsed again to be sent to the browser
	if _, err := f.Seek(0, os.SEEK_SET); err != nil {
		return fmt.Errorf("Failed to rewind cache entry: %w", err)
	}

	// Read in our stored response
	cacheRes, err := http.ReadResponse(bufio.NewReader(f), r.Request)
	if err != nil {
		return fmt.Errorf("Failed to parse on-disk cache entry: %w", err)
	}

	// Transparently replace the network response with the cached one on-disk
	*r = *cacheRes
	return nil
}

func errRes(s int) *http.Response {
	return &http.Response{StatusCode: s}
}

// controlSet checks if a Cache-Control option is set
func controlSet(h http.Header, c string) bool {
	if controls, ok := h["Cache-Control"]; ok {
		for _, control := range controls {
			control = strings.TrimSpace(strings.ToLower(control))
			if control == c {
				return true
			}
		}
	}

	return false
}

// doReq actually performs the upstream request (in the event of a cache miss)
func (c *Cache) doReq(r *http.Request) error {
	log.WithFields(log.Fields{
		"uri": r.RequestURI,
	}).Trace("Cache miss!")

	// Create a new request to the requested server
	r2, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		r.Response = errRes(http.StatusBadRequest)
		return fmt.Errorf("Bad request: %w", err)
	}

	// Tell the backend that we're proxying on behalf of the client
	r2.Header = r.Header
	r2.Header["X-Forwarded-For"] = []string{strings.Split(r.RemoteAddr, ":")[0]}

	// Actually do the request, and use RoundTrip to do it (http.Client does some caching stuff that will interfere
	// with us)
	res, err := http.DefaultTransport.RoundTrip(r2)
	if err != nil {
		r.Response = errRes(http.StatusBadGateway)
		return fmt.Errorf("Backend request failed: %w", err)
	}

	// Try and store the response in the cache, if allowed
	if err = c.Store(res); err != nil {
		r.Response = errRes(http.StatusInternalServerError)
		return err
	}
	r.Response = res
	return nil
}

// freshness calculates the freshness value for a stored response
// https://tools.ietf.org/id/draft-ietf-httpbis-cache-01.html#expiration.model
func freshness(r *http.Response) int64 {
	// Try first to read the Cache-Control s-maxage / max-age
	if controls, ok := r.Header["Cache-Control"]; ok {
		// Hack to make s-maxage appear first
		sort.Strings(controls)
		for _, control := range controls {
			control = strings.TrimSpace(strings.ToLower(control))
			if strings.HasPrefix(control, "s-maxage") || strings.HasPrefix(control, "max-age") {
				s := strings.Split(control, "=")
				if len(s) != 2 {
					continue
				}

				if f, err := strconv.ParseInt(s[1], 10, 64); err == nil {
					return f
				}
			}
		}
	}
	// Otherwise attempt to calculate based on Expires / Date headers
	if exp, ok := r.Header["Expires"]; ok && len(exp) == 1 {
		if e, err := http.ParseTime(exp[0]); err == nil {
			if date, ok := r.Header["Date"]; ok && len(date) == 1 {
				if d, err := http.ParseTime(date[0]); err == nil {
					return int64(e.Sub(d).Seconds())
				}
			}
		}
	}

	// TODO: Implement heuristic
	return 0
}

// age calculates the age of a stored response
// https://tools.ietf.org/id/draft-ietf-httpbis-cache-01.html#age.calculations
func age(f *os.File, r *http.Response) int64 {
	// Attempt to the age_value from the stored response
	var ageValue int64
	if ages, ok := r.Header["Age"]; ok && len(ages) == 1 {
		if age, err := strconv.ParseInt(ages[0], 10, 64); err != nil {
			ageValue = age
		}
	}

	// Attempt to read the value of the Date header from the stored response, falling back to the current time
	dateValue := time.Now().Unix()
	if date, ok := r.Header["Date"]; ok && len(date) == 1 {
		if d, err := http.ParseTime(date[0]); err == nil {
			dateValue = d.Unix()
		}
	}

	now := time.Now().Unix()

	// Attempt to read the response time as the modtime of the stored response file
	responseTime := dateValue
	if s, err := f.Stat(); err == nil {
		responseTime = s.ModTime().Unix()
	}

	var apparentAge int64
	apparentAge = 0
	if d := responseTime - dateValue; d > apparentAge {
		apparentAge = d
	}

	// TODO: Factor in request time
	correctedInitialAge := apparentAge
	if ageValue > correctedInitialAge {
		correctedInitialAge = ageValue
	}

	residentTime := now - responseTime
	return correctedInitialAge + residentTime
}

// Load transparently attempts to retrieve a HTTP response from cache, connecting to the backend as necessary
// https://tools.ietf.org/id/draft-ietf-httpbis-cache-01.html#constructing.responses.from.caches
func (c *Cache) Load(r *http.Request) error {
	if c.Path == "" {
		// If cache path is empty, caching is disabled
		return c.doReq(r)
	}

	// Attempt to find a response matching the keys in the request (Request URI, Path and varied headers)
	path, err := c.keyedPath("", r)
	if err != nil {
		return err
	}

	// Try to find open the stored response
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.Response = errRes(http.StatusInternalServerError)
			return fmt.Errorf("Failed to open cache entry for reading: %w", err)
		}

		// This response is definitely not cached based on the key
		return c.doReq(r)
	}

	// Parse the stored response
	res, err := http.ReadResponse(bufio.NewReader(f), r)
	if err != nil {
		f.Close()
		r.Response = errRes(http.StatusInternalServerError)
		return fmt.Errorf("Failed to parse on-disk cache entry: %w", err)
	}

	// TODO: Maybe consider HTTP/1.1 Pragma header
	mustRevalidate := controlSet(r.Header, "no-cache")
	if !mustRevalidate {
		mustRevalidate = controlSet(res.Header, "no-cache")
	}

	if !mustRevalidate {
		freshness := freshness(res)
		currentAge := age(f, res)

		// Is the stored response stale?
		if freshness > currentAge {
			log.WithFields(log.Fields{
				"path": path,
				"age":  currentAge,
			}).Trace("Request is fresh in cache")

			res.Header.Set("Age", fmt.Sprint(currentAge))
			r.Response = res
			return nil
		}
	}

	// TODO: Attempt to validate responses
	return c.doReq(r)
}

// proxyHTTP performs proxying of plain HTTP requests, with optional caching
func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"source": r.RemoteAddr,
		"method": r.Method,
		"url":    r.URL,
	}).Trace("Proxying HTTP request")

	// Load the response through the caching layer, which will transparently store / read cached responses
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
