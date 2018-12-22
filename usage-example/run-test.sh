#!/bin/bash -e

touch test.log

tail -f  test.log &
TAIL_PID=$!

go build -o ./tunnel ../main.go
go build -o ./sender sender.go
go build -o ./listener listener.go

# Start the server
# tunnel mux port: 9056
# management port: 9057
./tunnel -mode server -configFile server-config.json 2>&1  >> test.log  &
SERVER_PID=$!

# Start the "listener" test app 
# It listens on port 9001.  This would be your web  application server.
./listener  2>&1 >> test.log &
LISTENER_PID=$!

sleep 1

# Post the tunnels config to the management port of the tunnel server
# this would be done by the automation tool
echo "tunnel configuration:"
curl -s -X PUT -H "Content-Type: application/json" -d @tunnels.json localhost:9057/tunnels 2>&1 >> test.log 
echo ""
echo ""

# Start the client 
# Client Identifier: TestClient1
./tunnel -mode client -configFile client-config.json 2>&1 >> test.log &
CLIENT_PID=$!

sleep 1

# Start the "sender" test app 
# It connects to the front end port of the tunnel (port 9000).  This would be your end user who wants to use the web application.
./sender 2>&1  >> test.log  &
SENDER_PID=$!

sleep 1

echo "Wait 3 seconds then exit. "  >> test.log

sleep 3

kill -TERM $SERVER_PID
kill -TERM $CLIENT_PID
kill -TERM $LISTENER_PID
kill -TERM $TAIL_PID

rm test.log
rm tunnel
rm sender 
rm listener
