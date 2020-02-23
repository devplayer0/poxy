package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/devplayer0/poxy/internal/server"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func init() {
	level := log.InfoLevel
	if verbose := flag.Bool("-v", false, "write debug output"); *verbose {
		level = log.DebugLevel
	}
	if trace := flag.Bool("-trace", false, "write details about requests"); *trace {
		level = log.TraceLevel
	}

	if levelStr := os.Getenv("LOG"); levelStr != "" {
		if l, err := log.ParseLevel(levelStr); err == nil {
			level = l
		}
	}

	log.SetLevel(level)
}
func main() {
	s := server.NewServer()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	go func() {
		log.Info("Starting server...")
		if err := s.Start(); err != nil {
			log.WithField("err", err).Fatal("Failed to start server")
		}
	}()

	<-sigs
	if err := s.Stop(); err != nil {
		log.WithField("err", err).Fatal("Failed to stop server")
	}
}
