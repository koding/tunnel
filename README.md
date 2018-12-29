
## tunnel

This project was originally forked from https://github.com/koding/tunnel

It is intended to be used to make it easier for non-tech-savvy people to host web services that are avaliable on the public internet.

This repository only includes the application that does the tunneling part.  It does not include any other management or automation tools.

See the usage example folder for a basic test.

![Diagram](readme/Diagram.png)

### How it is intended to be used:

1. An automated tool creates a cloud instance and installs and configures the tunnel server on it. 
1. An automated tool installs the tunnel client on the self-hoster's server computer. 
1. An automated tool calls the `PUT /tunnels` api on the tunnel server's Management Port, and sends a JSON file describing which ports should be opened on the tunnel server, which client they should be tunneled to, and which ports on the client they should be tunneled to, as well as whether or not the HAProxy "PROXY" protocol should be used. This connection can use TLS Client Authentication.
1. The tunnel client connects to the tunnel server on the Tunnel Control Port. This connection can use TLS Client Authentication. This connection will be held open and re-created if dropped.
1. An internet user connects to the tunnel server on one of the ports defined in the JSON. The internet user's request is tunneled through the original connection from the tunnel client, and then proxied to the web server software running on the self-hoster's server computer.


### Output from Usage example showing how it works:

```
Starting the tunnel server with tunnel mux port: 9056, management port: 9057 

Starting the "listener" test app. It listens on port 9001.  This would be your web  application server.

Listener: I am listening on port 9001
Starting the tunnel client.  Client Identifier: TestClient1

Checking the list of connected clients.
HTTP GET localhost:9057/clients:
{"TestClient1":{"CurrentState":"ClientConnected","LastState":"ClientUnknown"}}

Sending the tunnel configuration to the server.
HTTP PUT localhost:9057/tunnels:
[{"HaProxyProxyProtocol":true,"FrontEndListenPort":9000,"BackEndPort":9001,"ClientIdentifier":"TestClient1"}]

Starting the "sender" test app. 
It connects to the front end port of the tunnel (port 9000).  This would be your end user who wants to use the web application.

Sender: I am dialing localhost:9000
Sender: sent 16 bytes
Listener: Someone connected from: 127.0.0.1:45516
Listener: read 16 bytes
Listener: the sender sent: Hello ! Hello! 

Listener: I am going to respond with "asd"
Listener: conn.Close()
Sender: read 3 bytes
Sender: Response from listener was: asd
Done. Now terminating forked processes and cleaning up.. 
./run-test.sh: line 70: 23044 Terminated              tail -f test.log
./run-test.sh: line 70: 23205 Terminated              ./tunnel -mode server -configFile server-config.json 2>&1 >> test.log
./run-test.sh: line 70: 23206 Terminated              ./listener 2>&1 >> test.log
./run-test.sh: line 70: 23218 Terminated              ./tunnel -mode client -configFile client-config.json 2>&1 >> test.log

```


### Why did you set it up this way?

I have a few requirements for this system. 

* It should be 100% automatable. It is intended to be used in a situation where it is unreasonable to ask the user to configure thier router, for example, they don't know how, they don't want to, or they are not allowed to (For example they live in a dorm where the University manages the network).
* Users have control over their own data.  We do not entrust cloud providers or 3rd parties with our data, TLS keys/certificates, etc. In terms of every day usage, this is a TLS connection from an internet user directly to the self-hoster's computer. It is opaque to the cloud provider. 
  * If the cloud provider wants to launch a Man in the Middle attack, even if they could obtain a trusted cert to use, it will not be easy to hide from the user as long as the user (or software that they installed) is anticipating it. (https://en.wikipedia.org/wiki/Certificate_Transparency) 
* It should support Failover/High Avaliability of services.  Therefore, it needs to be able to have multiple tunnel clients connected at once, which can be hot-swapped via a Management API.

### What did you add on top of the koding/tunnel package?

* A command line application which can be run in client mode or server mode based on a JSON config file. 
  * Optional TLS with Client Authentication
  * management API:
    * GET /clients
    * PUT /tunnnels
* Simplicity and Laser-like focus on "opaque" usage of TCP/TLS. Removed HTTP/WebSocket/Virtual Hosts code.
* Added support for HAProxy "PROXY" protocol. 
* Added support for Port mappings between front end and back end.
* Fixed various bugs related to connection lifecycle.

### How to build

```
go build -o tunnel -tags netgo 

# -tags netgo? what?
# this is a work around for dynamic linking on alpine linux
# see: https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host

docker build -t sequentialread/tunnel:0.0.1 .
```