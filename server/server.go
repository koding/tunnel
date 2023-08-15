package main

import (
	"flag"
	"fmt"
	"github.com/cajax/mylittleproxy"
	"go.uber.org/zap"
	"log"
	"net/http"
	"os"
)

func main() {
	configPath := flag.String("c", "config.json", "Path to server config file")
	flag.Parse()
	var config Config
	err := mylittleproxy.GetConfig(configPath, &config)

	if err != nil {
		log.Printf("Unable to read config: %s", err)
		os.Exit(1)
	}

	var logger *zap.Logger
	if config.Debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	defer logger.Sync()
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("Running server with ", *configPath)

	signatureKey := getSignatureKey(config, logger)

	cfg := &mylittleproxy.ServerConfig{
		SignatureKey:   signatureKey,
		AllowedHosts:   config.AllowedHosts,
		AllowedClients: config.AllowedClients,
		Log:            logger,
		ServeTCP:       config.ServeTCP,
	}
	server, _ := mylittleproxy.NewServer(cfg)
	//server.AddHost("sub.example.com", "1234")
	err = http.ListenAndServe(config.Listen, server)
	if err != nil {
		logger.Fatal("unable to start http server", zap.Error(err))
	}
}

func getSignatureKey(config Config, logger *zap.Logger) string {
	signatureKey := config.SignatureKey
	if signatureKey == "" {
		signatureKey = os.Getenv("MYLITTLEPROXY_SIGNATURE_KEY")
	}
	if signatureKey == "" {
		logger.Error("signature key must no be empty. Aborting")
		os.Exit(1)
	}
	return signatureKey
}

type Config struct {
	Debug          bool     `json:"debug"`
	SignatureKey   string   `json:"signatureKey"`
	Listen         string   `json:"listen"`
	AllowedHosts   []string `json:"allowedHosts"`
	AllowedClients []string `json:"allowedClients"`
	ServeTCP       bool     `json:"serveTCP"`
}
