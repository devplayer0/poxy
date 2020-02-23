package main

import (
	"os"
	"os/signal"

	"github.com/devplayer0/poxy/internal/server"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

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
