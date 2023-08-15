package main

import (
	"flag"
	"fmt"
	"github.com/cajax/mylittleproxy"
	"github.com/cajax/mylittleproxy/proto"
	"go.uber.org/zap"
	"log"
	"os"
)

func main() {
	configPath := getConfigPath()
	flag.Parse()
	var config Config
	err := mylittleproxy.GetConfig(configPath, &config)

	if err != nil {
		log.Printf("unable to read config: %s", err)
		os.Exit(1)
	}

	fmt.Println("Running server with ", *configPath)

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

	identifier := getIdentifier(config, logger)
	signatureKey := getSignatureKey(config, logger)

	if config.Proxy.Http.Domain == "" {
		logger.Error("proxied domain name must not be empty. Aborting")
		os.Exit(1)
	}

	if config.LocalAddress == "" {
		logger.Error("target local address must not be empty. Aborting")
		os.Exit(1)
	}

	httpRewrites := make([]proto.HTTPRewriteRule, 0)
	for _, r := range config.Proxy.Http.Rewrite {
		httpRewrites = append(httpRewrites, proto.HTTPRewriteRule{From: r.From, To: r.To})
	}

	if len(httpRewrites) == 0 {
		logger.Error("rewrite rules must contain at least une item. Aborting")
		os.Exit(1)
	}

	tunnelConfig := getTunnelConfig(identifier, config, httpRewrites, signatureKey, logger)

	client, err := mylittleproxy.NewClient(tunnelConfig)
	if err != nil {
		logger.Panic("unable to initialize client", zap.Error(err))
	}

	client.Start()
}

func getTunnelConfig(identifier string, config Config, httpRewrites []proto.HTTPRewriteRule, signatureKey string, logger *zap.Logger) *mylittleproxy.ClientConfig {
	cfg := &mylittleproxy.ClientConfig{
		Identifier: identifier,
		ServerAddr: config.ServerAddress,
		ConnectionConfig: proto.ConnectionConfig{
			Http: proto.HTTPConfig{
				Domain:  config.Proxy.Http.Domain,
				Rewrite: httpRewrites,
			},
		},
		LocalAddr:    config.LocalAddress,
		SignatureKey: signatureKey,
		Log:          logger,
	}
	return cfg
}

func getConfigPath() *string {
	configPath := flag.String("c", "config.json",
		`Path to client config file
Example of config file:
{
  "debug": true, <-- log debug information to console
  "identifier": "1234", <-- unique client ID. leave empty to use machine(host) ID. If server allow list is not empty then this ID must be present in the list
  "localAddress": "my.localhost.com:80", <-- host (and port) of target server to which we proxy HTTP calls
  "serverAddress": "localhost:8080", <-- address and port of proxy server
  "signatureKey": "secretkey", <-- secret key used to sign user identifier
  "proxy": {
    "http": {
      "domain": "1234.domain.com", <-- domain name associated by proxy server to this client
      "rewrite": [ <-- list of regex rules used to rewrite URLs. It must contain at least one rule like '/' -> '/'
        {
          "from": "/test",<-- you can use regex with matching groups
          "to": "/api/test" <-- you can insert matched groups using $x or named capture groups
        }
      ]
    }
  }
}`)
	return configPath
}

func getIdentifier(config Config, logger *zap.Logger) string {
	identifier := config.Identifier
	var err error
	if identifier == "" {

		identifier, err = os.Hostname()
		if err != nil {
			logger.Error("config filed doesn't have identifier and host name is not detected. Aborting")
			os.Exit(1)
		}
	}
	return identifier
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
	Debug         bool             `json:"debug"`
	Identifier    string           `json:"identifier"`
	LocalAddress  string           `json:"LocalAddress"`
	ServerAddress string           `json:"serverAddress"`
	SignatureKey  string           `json:"signatureKey"`
	Proxy         ConnectionConfig `json:"proxy"`
}

type ConnectionConfig struct {
	Http HTTPConfig `json:"http"`
}

type HTTPConfig struct {
	Domain  string            `json:"domain"`
	Rewrite []HTTPRewriteRule `json:"rewrite"`
}

type HTTPRewriteRule struct {
	From string `json:"from"`
	To   string `json:"to"`
}
