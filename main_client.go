package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	tunnel "git.sequentialread.com/forest/threshold/tunnel-lib"
)

type ClientConfig struct {
	DebugLog                   bool
	ClientId                   string
	MultiTenantSchedulerServer string
	ServerAddr                 string
	Servers                    []string
	ServiceToLocalAddrMap      *map[string]string
	CaCertificateFilesGlob     string
	ClientTlsKeyFile           string
	ClientTlsCertificateFile   string
	AdminUnixSocket            string
	Metrics                    MetricsConfig
}

type ClientServer struct {
	Client         *tunnel.Client
	ServerUrl      *url.URL
	ServerHostPort string
}

type LiveConfigUpdate struct {
	Listeners             []ListenerConfig
	ServiceToLocalAddrMap map[string]string
}

type clientAdminAPI struct{}

// Client State
var clientServers []ClientServer
var tlsClientConfig *tls.Config
var serviceToLocalAddrMap *map[string]string

func runClient(configFileName *string) {

	configBytes := getConfigBytes(configFileName)

	var config ClientConfig
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatalf("runClient(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
	}

	clientServers = []ClientServer{}
	makeServer := func(hostPort string) ClientServer {
		serverURLString := fmt.Sprintf("https://%s", hostPort)
		serverURL, err := url.Parse(serverURLString)
		if err != nil {
			log.Fatal(fmt.Errorf("failed to parse the ServerAddr (prefixed with https://) '%s' as a url", serverURLString))
		}
		return ClientServer{
			ServerHostPort: hostPort,
			ServerUrl:      serverURL,
		}
	}

	if config.MultiTenantSchedulerServer != "" {
		if config.ServerAddr != "" {
			log.Fatal("config contains both MultiTenantSchedulerServer and ServerAddr, only use one or the other")
		}
		if config.Servers != nil && len(config.Servers) > 0 {
			log.Fatal("config contains both MultiTenantSchedulerServer and Servers, only use one or the other")
		}
		// TODO Grab server host/ports from greenhouse

	} else if config.Servers != nil && len(config.Servers) > 0 {
		if config.ServerAddr != "" {
			log.Fatal("config contains both Servers and ServerAddr, only use one or the other")
		}
		for _, serverHostPort := range config.Servers {
			clientServers = append(clientServers, makeServer(serverHostPort))
		}
	} else {
		clientServers = []ClientServer{makeServer(config.ServerAddr)}
	}

	serviceToLocalAddrMap = config.ServiceToLocalAddrMap

	configToLog, _ := json.MarshalIndent(config, "", "  ")
	log.Printf("theshold client is starting up using config:\n%s\n", string(configToLog))

	dialFunction := net.Dial

	cert, err := tls.LoadX509KeyPair(config.ClientTlsCertificateFile, config.ClientTlsKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	commonName := cert.Leaf.Subject.CommonName
	clientIdDomain := strings.Split(commonName, "@")

	if len(clientIdDomain) != 2 {
		log.Fatal(fmt.Errorf(
			"expected TLS client certificate common name '%s' to match format '<clientId>@<domain>'", commonName,
		))
	}

	// This is enforced by the server anyways, so no need to enforce it here.
	// This allows server URLs to use IP addresses, don't require DNS.
	// if clientIdDomain[1] != serverURL.Hostname() {
	// 	log.Fatal(fmt.Errorf(
	// 		"expected TLS client certificate common name domain '%s' to match ServerAddr domain '%s'",
	// 		clientIdDomain[1], serverURL.Hostname(),
	// 	))
	// }

	if clientIdDomain[0] != config.ClientId {
		log.Fatal(fmt.Errorf(
			"expected TLS client certificate common name clientId '%s' to match ClientId '%s'",
			clientIdDomain[0], config.ClientId,
		))
	}

	certificates, err := filepath.Glob(config.CaCertificateFilesGlob)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	for _, filename := range certificates {
		caCert, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsClientConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsClientConfig.BuildNameToCertificate()

	dialFunction = func(network, address string) (net.Conn, error) {
		return tls.Dial(network, address, tlsClientConfig)
	}

	go runClientAdminApi(config)

	fetchLocalAddr := func(service string) (string, error) {
		//log.Printf("(*serviceToLocalAddrMap): %+v\n\n", (*serviceToLocalAddrMap))
		localAddr, hasLocalAddr := (*serviceToLocalAddrMap)[service]
		if !hasLocalAddr {
			return "", fmt.Errorf("service '%s' not configured. Set ServiceToLocalAddrMap in client config file or HTTP PUT /liveconfig over the AdminUnixSocket.", service)
		}
		return localAddr, nil
	}

	for _, server := range clientServers {
		clientStateChanges := make(chan *tunnel.ClientStateChange)
		tunnelClientConfig := &tunnel.ClientConfig{
			DebugLog:       config.DebugLog,
			Identifier:     config.ClientId,
			ServerAddr:     server.ServerHostPort,
			FetchLocalAddr: fetchLocalAddr,
			Dial:           dialFunction,
			StateChanges:   clientStateChanges,
		}

		client, err := tunnel.NewClient(tunnelClientConfig)
		if err != nil {
			log.Fatalf("runClient(): can't create tunnel client for %s because %v \n", server.ServerHostPort, err)
		}

		go (func() {
			for {
				stateChange := <-clientStateChanges
				log.Printf("%s clientStateChange: %s\n", server.ServerHostPort, stateChange.String())
			}
		})()

		server.Client = client
		go server.Client.Start()
	}

	log.Print("runClient(): the client should be running now\n")
}

func runClientAdminApi(config ClientConfig) {

	os.Remove(config.AdminUnixSocket)

	listenAddress, err := net.ResolveUnixAddr("unix", config.AdminUnixSocket)
	if err != nil {
		panic(fmt.Sprintf("runClient(): can't start because net.ResolveUnixAddr() returned %+v", err))
	}

	listener, err := net.ListenUnix("unix", listenAddress)
	if err != nil {
		panic(fmt.Sprintf("can't start because net.ListenUnix() returned %+v", err))
	}
	log.Printf("AdminUnixSocket Listening: %v\n\n", config.AdminUnixSocket)
	defer listener.Close()

	server := http.Server{
		Handler:      clientAdminAPI{},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err = server.Serve(listener)
	if err != nil {
		panic(fmt.Sprintf("AdminUnixSocket server returned %+v", err))
	}
}

// client admin api handler for /liveconfig over unix socket
func (handler clientAdminAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch path.Clean(request.URL.Path) {
	case "/liveconfig":
		if request.Method == "PUT" {
			requestBytes, err := ioutil.ReadAll(request.Body)
			if err != nil {
				log.Printf("clientAdminAPI: request read error: %+v\n\n", err)
				http.Error(response, "500 request read error", http.StatusInternalServerError)
				return
			}
			var configUpdate LiveConfigUpdate
			err = json.Unmarshal(requestBytes, &configUpdate)
			if err != nil {
				log.Printf("clientAdminAPI: can't parse JSON: %+v\n\n", err)
				http.Error(response, "400 bad request: can't parse JSON", http.StatusBadRequest)
				return
			}

			sendBytes, err := json.Marshal(configUpdate.Listeners)
			if err != nil {
				log.Printf("clientAdminAPI: Listeners json serialization failed: %+v\n\n", err)
				http.Error(response, "500 Listeners json serialization failed", http.StatusInternalServerError)
				return
			}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsClientConfig,
				},
				Timeout: 10 * time.Second,
			}

			// TODO make this concurrent requests, not one by one.
			for _, server := range clientServers {
				apiURL := fmt.Sprintf("https://%s/tunnels", server.ServerHostPort)
				tunnelsRequest, err := http.NewRequest("PUT", apiURL, bytes.NewReader(sendBytes))
				if err != nil {
					log.Printf("clientAdminAPI: error creating tunnels request: %+v\n\n", err)
					http.Error(response, "500 error creating tunnels request", http.StatusInternalServerError)
					return
				}
				tunnelsRequest.Header.Add("content-type", "application/json")

				tunnelsResponse, err := client.Do(tunnelsRequest)
				if err != nil {
					log.Printf("clientAdminAPI: Do(tunnelsRequest): %+v\n\n", err)
					http.Error(response, "502 tunnels request failed", http.StatusBadGateway)
					return
				}
				tunnelsResponseBytes, err := ioutil.ReadAll(tunnelsResponse.Body)
				if err != nil {
					log.Printf("clientAdminAPI: tunnelsResponse read error: %+v\n\n", err)
					http.Error(response, "502 tunnelsResponse read error", http.StatusBadGateway)
					return
				}

				if tunnelsResponse.StatusCode != http.StatusOK {
					log.Printf(
						"clientAdminAPI: tunnelsRequest returned HTTP %d: %s\n\n",
						tunnelsResponse.StatusCode, string(tunnelsResponseBytes),
					)
					http.Error(
						response,
						fmt.Sprintf("502 tunnels request returned HTTP %d", tunnelsResponse.StatusCode),
						http.StatusBadGateway,
					)
					return
				}
			}

			serviceToLocalAddrMap = &configUpdate.ServiceToLocalAddrMap

			response.Header().Add("content-type", "application/json")
			response.WriteHeader(http.StatusOK)
			response.Write(requestBytes)

		} else {
			response.Header().Set("Allow", "PUT")
			http.Error(response, "405 method not allowed, try PUT", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(response, "404 not found, try PUT /liveconfig", http.StatusNotFound)
	}

}
