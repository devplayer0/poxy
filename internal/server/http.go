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

func freshness(r *http.Response) int64 {
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
func age(f *os.File, r *http.Response) int64 {
	var ageValue int64
	if ages, ok := r.Header["Age"]; ok && len(ages) == 1 {
		if age, err := strconv.ParseInt(ages[0], 10, 64); err != nil {
			ageValue = age
		}
	}

	dateValue := time.Now().Unix()
	if date, ok := r.Header["Date"]; ok && len(date) == 1 {
		if d, err := http.ParseTime(date[0]); err == nil {
			dateValue = d.Unix()
		}
	}

	now := time.Now().Unix()

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

	// TODO: Maybe consider HTTP/1.1 Pragma header
	mustRevalidate := controlSet(r.Header, "no-cache")
	if !mustRevalidate {
		mustRevalidate = controlSet(res.Header, "no-cache")
	}

	if !mustRevalidate {
		freshness := freshness(res)
		currentAge := age(f, res)

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
