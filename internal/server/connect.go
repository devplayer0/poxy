package server

import (
	"fmt"
	"io"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func (s *Server) proxyCONNECT(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"source": r.RemoteAddr,
		"target": r.URL.Host,
	}).Trace("Performing CONNECT request")

	// Attempt to connect to the requested backend
	dstConn, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
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
		log.WithField("err", err).Error("Failed to hijack HTTP TCP connection")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	// Inform the client their proxy is good to go
	if _, err :=
		fmt.Fprintf(srcConn, "%v %v %v\r\n\r\n", r.Proto, http.StatusOK, "Connection Established"); err != nil {
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
		log.WithFields(log.Fields{
			"err": err,
		}).Warn("Error while proxying CONNECT data")
	}
}
