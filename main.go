package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	tunnel "git.sequentialread.com/forest/tunnel/tunnel-lib"
)

type ServerConfig struct {
	DebugLog                 bool
	TunnelControlPort        int
	ManagementPort           int
	UseTls                   bool
	CaCertificateFile        string
	ServerTlsKeyFile         string
	ServerTlsCertificateFile string
}

type ClientConfig struct {
	DebugLog                 bool
	ClientIdentifier         string
	ServerHost               string
	ServerTunnelControlPort  int
	ServerManagementPort     int
	UseTls                   bool
	CaCertificateFile        string
	ClientTlsKeyFile         string
	ClientTlsCertificateFile string
}

type ListenerConfig struct {
	HaProxyProxyProtocol bool
	ListenAddress        string
	ListenHostnameGlob   string
	ListenPort           int
	BackEndPort          int
	ClientIdentifier     string
}

type ClientState struct {
	CurrentState string
	LastState    string
}

// Server State
var listeners []ListenerConfig
var clientStatesMutex = &sync.Mutex{}
var clientStates map[string]ClientState
var server *tunnel.Server

// Client State
var client *tunnel.Client

func main() {

	mode := flag.String("mode", "", "Run client or server application. Allowed values: [client,server]")

	configFileName := flag.String("configFile", "config.json", "File path to JSON configuration file. Default value: config.json")

	flag.Parse()

	if mode != nil && *mode == "server" {
		runServer(configFileName)
	} else if mode != nil && *mode == "client" {
		runClient(configFileName)
	} else {
		fmt.Print("main(): required command line flag '-mode' was not set to one of the allowed values 'client' or 'server'.  Exiting.\n")
		os.Exit(1)
	}

}

func runClient(configFileName *string) {

	configBytes := getConfigBytes(configFileName)

	var config ClientConfig
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatalf("runClient(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
	}

	configToLog, _ := json.MarshalIndent(config, "", "  ")
	log.Printf("using config:\n%s\n", string(configToLog))

	dialFunction := net.Dial

	if config.UseTls {
		cert, err := tls.LoadX509KeyPair(config.ClientTlsCertificateFile, config.ClientTlsKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		caCert, err := ioutil.ReadFile(config.CaCertificateFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}
		tlsConfig.BuildNameToCertificate()

		dialFunction = func(network, address string) (net.Conn, error) {
			return tls.Dial(network, address, tlsConfig)
		}
	}

	tunnelClientConfig := &tunnel.ClientConfig{
		DebugLog:   config.DebugLog,
		Identifier: config.ClientIdentifier,
		ServerAddr: fmt.Sprintf("%s:%d", config.ServerHost, config.ServerTunnelControlPort),
		Dial:       dialFunction,
	}

	client, err = tunnel.NewClient(tunnelClientConfig)
	if err != nil {
		log.Fatalf("runClient(): can't create tunnel client because %s \n", err)
	}

	fmt.Print("runClient(): the client should be running now\n")
	client.Start()

}

func runServer(configFileName *string) {

	configBytes := getConfigBytes(configFileName)

	var config ServerConfig
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Printf("runServer(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
		os.Exit(1)
	}

	configToLog, _ := json.MarshalIndent(config, "", "  ")
	log.Printf("using config:\n%s\n", string(configToLog))

	clientStateChangeChannel := make(chan *tunnel.ClientStateChange)

	tunnelServerConfig := &tunnel.ServerConfig{
		StateChanges: clientStateChangeChannel,
		DebugLog:     config.DebugLog,
	}
	server, err = tunnel.NewServer(tunnelServerConfig)
	if err != nil {
		fmt.Printf("runServer(): can't create tunnel server because %s \n", err)
		os.Exit(1)
	}

	clientStates = make(map[string]ClientState)
	go (func() {
		for {
			clientStateChange := <-clientStateChangeChannel
			clientStatesMutex.Lock()
			previousState := ""
			currentState := clientStateChange.Current.String()
			fromMap, wasInMap := clientStates[clientStateChange.Identifier]
			if wasInMap {
				previousState = fromMap.CurrentState
			} else {
				previousState = clientStateChange.Previous.String()
			}
			if clientStateChange.Error != nil && clientStateChange.Error != io.EOF {
				log.Printf("runServer(): recieved a client state change with an error: %s \n", clientStateChange.Error)
				currentState = "ClientError"
			}
			clientStates[clientStateChange.Identifier] = ClientState{
				CurrentState: currentState,
				LastState:    previousState,
			}
			clientStatesMutex.Unlock()
		}
	})()

	if config.UseTls {
		caCert, err := ioutil.ReadFile(config.CaCertificateFile)
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig := &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		tlsConfig.BuildNameToCertificate()

		httpsManagementServer := &http.Server{
			Addr:      fmt.Sprintf(":%d", config.ManagementPort),
			TLSConfig: tlsConfig,
			Handler:   &(ManagementHttpHandler{}),
		}

		go (func() {
			httpsManagementServer.ListenAndServeTLS(config.ServerTlsCertificateFile, config.ServerTlsKeyFile)
		})()

		httpsTunnelServer := &http.Server{
			Addr:      fmt.Sprintf(":%d", config.TunnelControlPort),
			TLSConfig: tlsConfig,
			Handler:   server,
		}

		log.Print("runServer(): the server should be running now\n")
		httpsTunnelServer.ListenAndServeTLS(config.ServerTlsCertificateFile, config.ServerTlsKeyFile)

	} else {
		go (func() {
			http.ListenAndServe(fmt.Sprintf(":%d", config.ManagementPort), &(ManagementHttpHandler{}))
		})()

		log.Print("runServer(): the server should be running now\n")
		http.ListenAndServe(fmt.Sprintf(":%d", config.TunnelControlPort), server)
	}

}

func setListeners(listenerConfigs []ListenerConfig) (int, string) {
	currentListenersThatCanKeepRunning := make([]ListenerConfig, 0)
	newListenersThatHaveToBeAdded := make([]ListenerConfig, 0)

	for _, newListenerConfig := range listenerConfigs {
		clientState, everHeardOfClientBefore := clientStates[newListenerConfig.ClientIdentifier]
		if !everHeardOfClientBefore {
			return http.StatusNotFound, fmt.Sprintf("Client %s Not Found", newListenerConfig.ClientIdentifier)
		}
		if clientState.CurrentState != tunnel.ClientConnected.String() {
			return http.StatusNotFound, fmt.Sprintf("Client %s is not connected it is %s", newListenerConfig.ClientIdentifier, clientState.CurrentState)
		}
	}

	for _, existingListener := range listeners {
		canKeepRunning := false
		for _, newListenerConfig := range listenerConfigs {
			if compareListenerConfigs(existingListener, newListenerConfig) {
				canKeepRunning = true
			}
		}

		if !canKeepRunning {
			listenAddress := net.ParseIP(existingListener.ListenAddress)
			if listenAddress == nil {
				return http.StatusBadRequest, fmt.Sprintf("Bad Request: \"%s\" is not an IP address.", existingListener.ListenAddress)
			}

			server.DeleteAddr(listenAddress, existingListener.ListenPort, existingListener.ListenHostnameGlob)

		} else {
			currentListenersThatCanKeepRunning = append(currentListenersThatCanKeepRunning, existingListener)
		}
	}

	for _, newListenerConfig := range listenerConfigs {
		hasToBeAdded := true
		for _, existingListener := range listeners {
			if compareListenerConfigs(existingListener, newListenerConfig) {
				hasToBeAdded = false
			}
		}

		if hasToBeAdded {
			listenAddress := net.ParseIP(newListenerConfig.ListenAddress)
			//fmt.Printf("str: %s, listenAddress: %s\n\n", newListenerConfig.ListenAddress, listenAddress)
			if listenAddress == nil {
				return http.StatusBadRequest, fmt.Sprintf("Bad Request: \"%s\" is not an IP address.", newListenerConfig.ListenAddress)
			}
			err := server.AddAddr(
				listenAddress,
				newListenerConfig.ListenPort,
				newListenerConfig.ListenHostnameGlob,
				newListenerConfig.ClientIdentifier,
				newListenerConfig.HaProxyProxyProtocol,
				newListenerConfig.BackEndPort,
			)

			if err != nil {
				if strings.Contains(err.Error(), "already in use") {
					return http.StatusConflict, fmt.Sprintf("Port Conflict Port %s already in use", listenAddress)
				}

				log.Printf("setListeners(): can't net.Listen(\"tcp\", \"%s\")  because %s \n", listenAddress, err)
				return http.StatusInternalServerError, "Unknown Listening Error"
			}

			newListenersThatHaveToBeAdded = append(newListenersThatHaveToBeAdded, newListenerConfig)
		}
	}

	listeners = append(currentListenersThatCanKeepRunning, newListenersThatHaveToBeAdded...)

	return http.StatusOK, "ok"

}

func compareListenerConfigs(a, b ListenerConfig) bool {
	return (a.ListenPort == b.ListenPort &&
		a.ListenAddress == b.ListenAddress &&
		a.ListenHostnameGlob == b.ListenHostnameGlob &&
		a.BackEndPort == b.BackEndPort &&
		a.ClientIdentifier == b.ClientIdentifier &&
		a.HaProxyProxyProtocol == b.HaProxyProxyProtocol)
}

type ManagementHttpHandler struct{}

func (s *ManagementHttpHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

	switch fmt.Sprintf("%s/", path.Clean(request.URL.Path)) {
	case "/clients/":
		if request.Method == "GET" {
			clientStatesMutex.Lock()
			bytes, err := json.Marshal(clientStates)
			clientStatesMutex.Unlock()
			if err != nil {
				http.Error(responseWriter, "500 JSON Marshal Error", http.StatusInternalServerError)
				return
			}
			responseWriter.Header().Set("Content-Type", "application/json")
			responseWriter.Write(bytes)

		} else {
			responseWriter.Header().Set("Allow", "PUT")
			http.Error(responseWriter, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
	case "/tunnels/":
		if request.Method == "PUT" {
			if request.Header.Get("Content-Type") != "application/json" {
				http.Error(responseWriter, "415 Unsupported Media Type: Content-Type must be application/json", http.StatusUnsupportedMediaType)
			} else {
				bodyBytes, err := ioutil.ReadAll(request.Body)
				if err != nil {
					http.Error(responseWriter, "500 Read Error", http.StatusInternalServerError)
					return
				}
				var listenerConfigs []ListenerConfig
				err = json.Unmarshal(bodyBytes, &listenerConfigs)
				if err != nil {
					http.Error(responseWriter, "422 Unprocessable Entity: Can't Parse JSON", http.StatusUnprocessableEntity)
					return
				}

				statusCode, errorMessage := setListeners(listenerConfigs)

				if statusCode != 200 {
					http.Error(responseWriter, errorMessage, statusCode)
					return
				}

				bytes, err := json.Marshal(listenerConfigs)
				if err != nil {
					http.Error(responseWriter, "500 JSON Marshal Error", http.StatusInternalServerError)
					return
				}

				responseWriter.Header().Set("Content-Type", "application/json")
				responseWriter.Write(bytes)
			}
		} else {
			responseWriter.Header().Set("Allow", "PUT")
			http.Error(responseWriter, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		}
	case "/ping/":
		if request.Method == "GET" {
			fmt.Fprint(responseWriter, "pong")
		} else {
			responseWriter.Header().Set("Allow", "GET")
			http.Error(responseWriter, "405 method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(responseWriter, "404 not found. Try GET /ping or PUT /tunnels.", http.StatusNotFound)
	}
}

func getConfigBytes(configFileName *string) []byte {
	if configFileName != nil {
		configBytes, err := ioutil.ReadFile(*configFileName)
		if err != nil {
			log.Printf("getConfigBytes(): can't ioutil.ReadFile(*configFileName) because %s \n", err)
			os.Exit(1)
		}
		return configBytes
	} else {
		log.Printf("getConfigBytes(): configFileName was nil.")
		os.Exit(1)
		return nil
	}
}
