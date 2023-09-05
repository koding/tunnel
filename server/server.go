package main

import (
	"flag"
	"fmt"
	"github.com/cajax/mylittleproxy/proto"
	"github.com/cajax/mylittleproxy/tunnel"
	"go.uber.org/zap"
	"log"
	"net/http"
	"os"
)

func main() {
	configPath := flag.String("c", tunnel.GetExecutableDir()+string(os.PathSeparator)+"config.json", "Path to server config file")
	flag.Parse()
	var config Config
	err := tunnel.GetConfig(configPath, &config)

	if err != nil {
		log.Printf("Unable to read config: %s", err)
		os.Exit(1)
	}

	var logger *zap.Logger
	if config.Debug {
		logger = zap.Must(zap.NewDevelopment())
	} else {
		logger = zap.Must(zap.NewProduction())
	}
	defer logger.Sync()

	fmt.Println("Running server with ", *configPath)

	signatureKey := getSignatureKey(config, logger)

	controlPath := proto.DefaultControlPath

	if config.ControlPath != "" {
		controlPath = config.ControlPath
	}

	cfg := &tunnel.ServerConfig{
		SignatureKey:   signatureKey,
		AllowedHosts:   config.AllowedHosts,
		AllowedClients: config.AllowedClients,
		Log:            logger,
		ControlPath:    controlPath,
	}
	server, _ := tunnel.NewServer(cfg)
	logger.Info("Listening", zap.String("control_url", config.Listen+controlPath))
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
	ControlPath    string   `json:"controlPath"`
}
