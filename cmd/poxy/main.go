package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/devplayer0/poxy/internal/server"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var addr string
var cachePath string

func init() {
	verbose := flag.Bool("v", false, "write debug output")
	trace := flag.Bool("trace", false, "write details about requests")
	flag.StringVar(&addr, "addr", ":8080", "Listen address")
	flag.StringVar(&cachePath, "cache", "", "enable caching in directory")
	flag.Parse()

	level := log.InfoLevel
	if *verbose {
		level = log.DebugLevel
	}
	if *trace {
		level = log.TraceLevel
	}

	if levelStr := os.Getenv("LOG"); levelStr != "" {
		if l, err := log.ParseLevel(levelStr); err == nil {
			level = l
		}
	}

	if p := os.Getenv("CACHE_PATH"); p != "" {
		cachePath = p
	}

	log.SetLevel(level)
}
func main() {
	s, err := server.NewServer(addr, cachePath)
	if err != nil {
		log.WithField("err", err).Fatal("Failed to create server")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	go func() {
		log.Info("Starting server...")
		if err := s.Start(); err != nil {
			log.WithField("err", err).Fatal("Failed to start server")
		}
	}()

	<-sigs
	log.Info("Shutting down...")
	if err := s.Stop(); err != nil {
		log.WithField("err", err).Fatal("Failed to stop server")
	}
}
