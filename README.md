
## tunnel

This project was originally forked from https://github.com/koding/tunnel

It is intended to be used to make it easier for non-tech-savvy people to host web services that are avaliable on the public internet.

![Diagram](readme/Diagram.png)

### How it works:

1. An automated tool creates a cloud instance and installs and configures the tunnel server on it. 
1. An automated tool installs the tunnel client on the self-hoster's server computer.
1. The tunnel client connects to the tunnel server on the Tunnel Control Port. This connection will use TLS Client Authentication. This connection will be held open and re-created if dropped. 
1. An automated tool calls the `PUT /tunnels` api on the tunnel server's Management Port, and sends a JSON file describing which ports should be opened on the tunnel server, which client they should be tunneled to, and which ports on the client they should be tunneled to, as well as whether or not the HAProxy "PROXY" protocol should be used. This connection will also use TLS Client Authentication.
1. An internet user connects to the tunnel server on one of the ports defined in the JSON. The internet user's request is tunneled through the original connection from the tunnel client, and then proxied to the web server software running on the self-hoster's server computer.

### Why did you set it up this way?

I have a few requirements for this system. 

1. It should be 100% automatable. It is intended to be used in a situation where it is unreasonable to ask the user to configure thier router, for example, they don't know how, they don't want to, or they are not allowed to (For example they live in a dorm where the University manages the network).
1. Users have control over their own data.  We do not entrust cloud providers or 3rd parties with our data, TLS keys/certificates, etc. In terms of every day usage, this is a TLS connection from an internet user directly to the self-hoster's computer. It is opaque to the cloud provider. 
1. It should support Failover/High Avaliability of services.  Therefore, it needs to be able to have multiple tunnel clients connected at once, which can be hot-swapped via a Management API.

### What did you add on top of the koding/tunnel package?

1. A command line application which can be run in client mode or server mode based on a JSON config file.
1. Simplicity and Laser-like focus on "opaque" usage of TCP/TLS. Removed HTTP/WebSocket/Virtual Hosts code.
1. Added support for HAProxy "PROXY" protocol. 
1. Added support for Port mappings between front end and back end.
1. Fixed various bugs related to connection lifecycle.