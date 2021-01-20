package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

type MetricsConfig struct {
	PrometheusMetricsAPIPort int
}

type ListenerConfig struct {
	HaProxyProxyProtocol bool
	ListenAddress        string
	ListenHostnameGlob   string
	ListenPort           int
	BackEndService       string
	ClientId             string
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

func intSlice2StringSlice(slice []int) []string {
	toReturn := make([]string, len(slice))
	for i, integer := range slice {
		toReturn[i] = strconv.Itoa(integer)
	}
	return toReturn
}

func stringSliceMap(slice []string, mapper func(string) string) []string {
	toReturn := make([]string, len(slice))
	for i, str := range slice {
		toReturn[i] = mapper(str)
	}
	return toReturn
}
