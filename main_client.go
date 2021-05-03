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
	"regexp"
	"strings"
	"time"

	tunnel "git.sequentialread.com/forest/threshold/tunnel-lib"
)

type ClientConfig struct {
	DebugLog                   bool
	ClientId                   string
	GreenhouseDomain           string
	GreenhouseAPIToken         string
	GreenhouseThresholdPort    int
	ServerAddr                 string
	Servers                    []string
	ServiceToLocalAddrMap      *map[string]string
	CaCertificateFilesGlob     string
	ClientTlsKeyFile           string
	ClientTlsCertificateFile   string
	CaCertificate              string
	ClientTlsKey               string
	ClientTlsCertificate       string
	AdminUnixSocket            string
	AdminAPIPort               int
	AdminAPICACertificateFile  string
	AdminAPITlsKeyFile         string
	AdminAPITlsCertificateFile string
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

type ThresholdTenantInfo struct {
	ThresholdServers []string
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

	if config.GreenhouseThresholdPort == 0 {
		config.GreenhouseThresholdPort = 9056
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

	if config.GreenhouseDomain != "" {
		if config.ServerAddr != "" {
			log.Fatal("config contains both GreenhouseDomain and ServerAddr, only use one or the other")
		}
		if config.Servers != nil && len(config.Servers) > 0 {
			log.Fatal("config contains both GreenhouseDomain and Servers, only use one or the other")
		}
		if config.GreenhouseAPIToken == "" {
			log.Fatal("config contains GreenhouseDomain but does not contain GreenhouseAPIToken, use both or niether")
		}

		greenhouseClient := http.Client{Timeout: time.Second * 10}
		greenhouseURL := fmt.Sprintf("https://%s/api/tenant_info", config.GreenhouseDomain)
		request, err := http.NewRequest("GET", greenhouseURL, nil)
		if err != nil {
			log.Fatal("invalid GreenhouseDomain '%s', can't create http request for %s", config.GreenhouseDomain, greenhouseURL)
		}
		request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", config.GreenhouseAPIToken))

		response, err := greenhouseClient.Do(request)
		if err != nil || response.StatusCode != 200 {
			if err == nil {
				if response.StatusCode == 401 {
					log.Fatalf("bad or expired GreenhouseAPIToken, recieved HTTP 401 Unauthorized from Greenhouse server %s", greenhouseURL)
				} else {
					log.Fatalf("server error: recieved HTTP %d from Greenhouse server %s", response.StatusCode, greenhouseURL)
				}
			}
			log.Printf("can't reach %s, falling back to DNS lookup...\n", greenhouseURL)
			ips, err := net.LookupIP(config.GreenhouseDomain)
			if err != nil {
				log.Fatalf("Failed to lookup GreenhouseDomain '%s'", config.GreenhouseDomain)
			}
			for _, ip := range ips {
				clientServers = append(clientServers, makeServer(fmt.Sprintf("%s:%d", ip, config.GreenhouseThresholdPort)))
			}
		} else {
			responseBytes, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Fatal("http read error GET '%s'", greenhouseURL)
			}
			var tenantInfo ThresholdTenantInfo
			err = json.Unmarshal(responseBytes, &tenantInfo)
			if err != nil {
				log.Fatal("http read error GET '%s'", greenhouseURL)
			}
			for _, serverHostPort := range tenantInfo.ThresholdServers {
				clientServers = append(clientServers, makeServer(serverHostPort))
			}
		}

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

	if config.ServiceToLocalAddrMap != nil {
		serviceToLocalAddrMap = config.ServiceToLocalAddrMap
	} else {
		serviceToLocalAddrMap = &(map[string]string{})
	}

	configToLog, _ := json.MarshalIndent(config, "", "  ")
	configToLogString := string(configToLog)

	configToLogString = regexp.MustCompile(
		`("GreenhouseAPIToken": ")[^"]+(",)`,
	).ReplaceAllString(
		configToLogString,
		"$1******$2",
	)

	log.Printf("theshold client is starting up using config:\n%s\n", configToLogString)

	dialFunction := net.Dial

	var cert tls.Certificate
	hasFiles := config.ClientTlsCertificateFile != "" && config.ClientTlsKeyFile != ""
	hasLiterals := config.ClientTlsCertificate != "" && config.ClientTlsKey != ""
	if hasFiles && !hasLiterals {
		cert, err = tls.LoadX509KeyPair(config.ClientTlsCertificateFile, config.ClientTlsKeyFile)
		if err != nil {
			log.Fatal(fmt.Sprintf("can't start because tls.LoadX509KeyPair returned: \n%+v\n", err))
		}
	} else if !hasFiles && hasLiterals {
		cert, err = tls.X509KeyPair([]byte(config.ClientTlsCertificate), []byte(config.ClientTlsKey))
		if err != nil {
			log.Fatal(fmt.Sprintf("can't start because tls.X509KeyPair returned: \n%+v\n", err))
		}

	} else {
		log.Fatal("one or the other (not both) of ClientTlsCertificateFile+ClientTlsKeyFile or ClientTlsCertificate+ClientTlsKey is required\n")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	if parsedCert == nil {
		log.Fatalf("parsedCert is nil (%s)", config.ClientTlsCertificateFile)
	}
	commonName := parsedCert.Subject.CommonName
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

	caCertPool := x509.NewCertPool()
	if config.CaCertificateFilesGlob != "" && config.CaCertificate == "" {
		certificates, err := filepath.Glob(config.CaCertificateFilesGlob)
		if err != nil {
			log.Fatal(err)
		}

		for _, filename := range certificates {
			caCert, err := ioutil.ReadFile(filename)
			if err != nil {
				log.Fatal(err)
			}
			ok := caCertPool.AppendCertsFromPEM(caCert)
			if !ok {
				log.Fatalf("Failed to add CA certificate '%s' to cert pool\n", filename)
			}
		}
	} else if config.CaCertificateFilesGlob == "" && config.CaCertificate != "" {
		ok := caCertPool.AppendCertsFromPEM([]byte(config.CaCertificate))
		if !ok {
			log.Fatal("Failed to add config.CaCertificate to cert pool\n")
		}
	} else {
		log.Fatal("one or the other (not both) of CaCertificateFilesGlob or CaCertificate is required\n")
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
			return "", fmt.Errorf("service '%s' not configured. Set ServiceToLocalAddrMap in client config file or HTTP PUT /liveconfig over the admin api.", service)
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

	blockForever := make(chan int)
	<-blockForever
}

func runClientAdminApi(config ClientConfig) {

	var listener net.Listener
	if config.AdminUnixSocket != "" && config.AdminAPIPort == 0 {
		os.Remove(config.AdminUnixSocket)

		listenAddress, err := net.ResolveUnixAddr("unix", config.AdminUnixSocket)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ResolveUnixAddr() returned %+v", err))
		}

		listener, err = net.ListenUnix("unix", listenAddress)
		if err != nil {
			panic(fmt.Sprintf("can't start because net.ListenUnix() returned %+v", err))
		}
		log.Printf("AdminUnixSocket Listening: %v\n\n", config.AdminUnixSocket)
		defer listener.Close()
	} else if config.AdminUnixSocket == "" && config.AdminAPIPort != 0 {
		addrString := fmt.Sprintf("127.0.0.1:%d", config.AdminAPIPort)
		addr, err := net.ResolveTCPAddr("tcp", addrString)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ResolveTCPAddr(%s) returned %+v", addrString, err))
		}
		tcpListener, err := net.ListenTCP("tcp", addr)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because net.ListenTCP(%s) returned %+v", addrString, err))
		}

		caCertPool := x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(config.AdminAPICACertificateFile)
		if err != nil {
			panic(fmt.Sprintf("runClient(): can't start because ioutil.ReadFile(%s) returned %+v", config.AdminAPICACertificateFile, err))
		}
		caCertPool.AppendCertsFromPEM(caCertBytes)

		tlsCert, err := tls.LoadX509KeyPair(config.AdminAPITlsCertificateFile, config.AdminAPITlsKeyFile)
		if err != nil {
			panic(fmt.Sprintf(
				"runClient(): can't start because tls.LoadX509KeyPair(%s,%s) returned %+v",
				config.AdminAPITlsCertificateFile, config.AdminAPITlsKeyFile, err,
			))
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		tlsConfig.BuildNameToCertificate()

		listener = tls.NewListener(tcpListener, tlsConfig)
	} else if config.AdminUnixSocket != "" && config.AdminAPIPort != 0 {
		log.Fatal("One or the other (and not both) of AdminUnixSocket or AdminAPIPort is required")
		return
	} else if config.AdminUnixSocket == "" && config.AdminAPIPort == 0 {
		return
	}

	server := http.Server{
		Handler:      clientAdminAPI{},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	err := server.Serve(listener)
	if err != nil {
		panic(fmt.Sprintf("Admin API server returned %+v", err))
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
						fmt.Sprintf("502 tunnels request returned HTTP %d: %s", tunnelsResponse.StatusCode, string(tunnelsResponseBytes)),
						http.StatusBadGateway,
					)
					return
				}
			}

			if &configUpdate.ServiceToLocalAddrMap != nil {
				serviceToLocalAddrMap = &configUpdate.ServiceToLocalAddrMap
			}

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
