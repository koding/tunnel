package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

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
	BackEndPort        int
	ClientIdentifier   string
}

type Listener struct {
	NetListener net.Listener
	Config      ListenerConfig
}

type ClientState struct {
	CurrentState string
	LastState    string
}

// Server State
var listeners []Listener
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
		fmt.Printf("runClient(): can't json.Unmarshal(configBytes, &config) because %s \n", err)
		os.Exit(1)
	}

	tunnelClientConfig := &tunnel.ClientConfig{
		DebugLog:   config.DebugLog,
		Identifier: config.ClientIdentifier,
		ServerAddr: fmt.Sprintf("%s:%d", config.ServerHost, config.ServerTunnelControlPort),
	}

	client, err = tunnel.NewClient(tunnelClientConfig)
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
			if clientStateChange.Error != nil {
				fmt.Printf("runServer(): recieved a client state change with an error: %s \n", err)
				currentState = "ClientError"
			}
			clientStates[clientStateChange.Identifier] = ClientState{
				CurrentState: currentState,
				LastState:    previousState,
			}
			clientStatesMutex.Unlock()
		}
	})()

	go (func() {
		http.ListenAndServe(fmt.Sprintf(":%d", config.ManagementPort), &(ManagementHttpHandler{}))
	})()

	//HTTP server for the control connection.
	http.ListenAndServe(fmt.Sprintf(":%d", config.TunnelControlPort), server)
}

func setListeners(listenerConfigs []ListenerConfig) (int, string) {
	currentListenersThatCanKeepRunning := make([]Listener, 0)
	newListenersThatHaveToBeAdded := make([]Listener, 0)

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
			if compareListenerConfigs(existingListener.Config, newListenerConfig) {
				canKeepRunning = true
			}
		}

		if !canKeepRunning {
			server.DeleteAddr(existingListener.NetListener, nil)

			// Do I care if this returned an error? No, I do not. See:
			// https://github.com/golang/go/blob/master/src/net/net.go#L197
			existingListener.NetListener.Close()

		} else {
			currentListenersThatCanKeepRunning = append(currentListenersThatCanKeepRunning, existingListener)
		}
	}

	for _, newListenerConfig := range listenerConfigs {
		hasToBeAdded := true
		for _, existingListener := range listeners {
			if compareListenerConfigs(existingListener.Config, newListenerConfig) {
				hasToBeAdded = false
			}
		}

		if hasToBeAdded {
			listenAddress := fmt.Sprintf(":%d", newListenerConfig.FrontEndListenPort)
			netListener, err := net.Listen("tcp", listenAddress)
			if err != nil {
				if strings.Contains(err.Error(), "already in use") {
					return http.StatusConflict, fmt.Sprintf("Port Conflict Port %s already in use", listenAddress)
				} else {
					fmt.Printf("setListeners(): can't net.Listen(\"tcp\", \"%s\")  because %s \n", listenAddress, err)
					return http.StatusInternalServerError, "Unknown Listening Error"
				}
			}
			server.AddAddr(netListener, nil, newListenerConfig.ClientIdentifier, newListenerConfig.ProxyProtocol, newListenerConfig.BackEndPort)
			newListenersThatHaveToBeAdded = append(newListenersThatHaveToBeAdded, Listener{NetListener: netListener, Config: newListenerConfig})
		}
	}

	listeners = append(currentListenersThatCanKeepRunning, newListenersThatHaveToBeAdded...)

	return http.StatusOK, "ok"

}

func compareListenerConfigs(a, b ListenerConfig) bool {
	return (a.BackEndPort == b.BackEndPort &&
		a.ClientIdentifier == b.ClientIdentifier &&
		a.FrontEndListenPort == b.FrontEndListenPort &&
		a.ProxyProtocol == b.ProxyProtocol)
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
