package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"

	tunnel "git.sequentialread.com/forest/tunnel/tunnel-lib"
)

type ServerConfig struct {
	DebugLog          bool
	TunnelControlPort int
	ManagementPort    int
}

type ClientConfig struct {
	DebugLog                bool
	ClientIdentifier        string
	ServerHost              string
	ServerTunnelControlPort int
	ServerManagementPort    int
}

type ListenerConfig struct {
	ProxyProtocol      bool
	FrontEndListenPort int
	BackEndListenPort  int
}

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
		fmt.Printf("runClient(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
		os.Exit(1)
	}

	tunnelClientConfig := &tunnel.ClientConfig{
		DebugLog:   config.DebugLog,
		Identifier: config.ClientIdentifier,
		ServerAddr: fmt.Sprintf("%s:%d", config.ServerHost, config.ServerTunnelControlPort),
	}

	client, err := tunnel.NewClient(tunnelClientConfig)
	if err != nil {
		fmt.Printf("runClient(): can't create tunnel client because %s \n", err)
		os.Exit(1)
	}

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

	tunnelServerConfig := &tunnel.ServerConfig{
		DebugLog: config.DebugLog,
	}
	server, err := tunnel.NewServer(tunnelServerConfig)
	if err != nil {
		fmt.Printf("runServer(): can't create tunnel server because %s \n", err)
		os.Exit(1)
	}

	go (func() {
		http.ListenAndServe(fmt.Sprintf(":%d", config.ManagementPort), &(ManagementHttpHandler{}))
	})()

	//HTTP server for the control connection.
	http.ListenAndServe(fmt.Sprintf(":%d", config.TunnelControlPort), server)
}

func setListeners(listenerConfigs []ListenerConfig) {

}

type ManagementHttpHandler struct{}

func (s *ManagementHttpHandler) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

	switch fmt.Sprintf("%s/", path.Clean(request.URL.Path)) {
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

				setListeners(listenerConfigs)

				bytes, err := json.Marshal(listenerConfigs)
				if err != nil {
					http.Error(responseWriter, "500 Marshal Error", http.StatusInternalServerError)
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
			fmt.Fprint(responseWriter, "pong!")
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
			fmt.Printf("runClient(): can't ioutil.ReadFile(*configFileName) because %s \n", err)
			os.Exit(1)
		}
		return configBytes
	} else {
		fmt.Printf("runClient(): configFileName was nil.")
		os.Exit(1)
		return nil
	}
}
