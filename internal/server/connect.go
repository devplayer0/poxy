package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

func (s *Server) proxyCONNECT(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"source": r.RemoteAddr,
		"target": r.URL.Host,
	}).Debug("Performing CONNECT request")
	info := ReqInfo{
		Status: http.StatusOK,
		Type:   "connect",
		Time:   time.Now().Unix(),
		Method: http.MethodConnect,
		URL:    r.URL.Host,
	}
	defer s.publishJSON(reqStream, &info)

	// Attempt to connect to the requested backend
	start := time.Now()
	dstConn, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
		info.Type = "failed"
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "CONNECT failed: %v", err)
		return
	}
	defer dstConn.Close()

	// Hihacking the connection stops the server from sending any more HTTP "stuff" and gives us access to the raw TCP
	// connection
	hj := w.(http.Hijacker)
	srcConn, srcRw, err := hj.Hijack()
	if err != nil {
		info.Type = "failed"
		log.WithField("err", err).Error("Failed to hijack HTTP TCP connection")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	// Inform the client their proxy is good to go
	if _, err :=
		fmt.Fprintf(srcConn, "%v %v %v\r\n\r\n", r.Proto, http.StatusOK, "Connection Established"); err != nil {
		info.Type = "failed"
		log.WithField("err", err).Error("Failed to send Connection Established message")
		return
	}

	// Pipe between client, backend and vice-versa
	errChan := make(chan error)
	go func() {
		_, err := io.Copy(srcRw, dstConn)
		errChan <- err

		srcConn.Close()
	}()
	go func() {
		_, err := io.Copy(dstConn, srcRw)
		errChan <- err

		dstConn.Close()
	}()

	if <-errChan != nil {
		info.Type = "failed"
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Error while proxying CONNECT data")
		return
	}
	info.Duration = time.Now().Sub(start).Milliseconds()
	log.WithField("time", info.Duration).Debug("Request time (ms)")
}
