#!/bin/bash -e

touch test.log

tail -f  test.log &
TAIL_PID=$!

go build -o ./tunnel ../main.go
go build -o ./sender sender.go
go build -o ./listener listener.go

echo "Starting the tunnel server with tunnel mux port: 9056, management port: 9057 "
echo ""

./tunnel -mode server -configFile server-config.json 2>&1  >> test.log  &
SERVER_PID=$!

echo "Starting the \"listener\" test app. It listens on port 9001.  This would be your web  application server."
echo ""

./listener  2>&1 >> test.log &
LISTENER_PID=$!

sleep 1


echo "Starting the tunnel client.  Client Identifier: TestClient1"
echo ""
./tunnel -mode client -configFile client-config.json 2>&1 >> test.log &
CLIENT_PID=$!

sleep 1



# Check the list of connected clients
# this would be done by the automation tool to validate that the subsequent request should succeed
# instead of getting "404 Client TestClient1 is not connected"
echo "Checking the list of connected clients."
echo "HTTP GET localhost:9057/clients:"
curl --cacert "InternalCA+chain.crt" \
  --key "TestClient1@example.com.key" \
  --cert "TestClient1@example.com+chain.crt" \
  -s https://localhost:9057/clients 2>&1 >> test.log 
echo ""
echo ""

# Post the tunnels config to the management port of the tunnel server
# this would be done by the automation tool
echo "Sending the tunnel configuration to the server."
echo "HTTP PUT localhost:9057/tunnels:"
curl --cacert "InternalCA+chain.crt" \
  --key "TestClient1@example.com.key" \
  --cert "TestClient1@example.com+chain.crt" \
   -s -X PUT -H "Content-Type: application/json" -d @tunnels.json https://localhost:9057/tunnels 2>&1 >> test.log 
echo ""
echo ""

sleep 1

echo "Starting the \"sender\" test app. "
echo "It connects to the front end port of the tunnel (port 9000).  This would be your end user who wants to use the web application."
echo ""

./sender 2>&1  >> test.log  &
SENDER_PID=$!

sleep 1

echo "Done. Now terminating forked processes and cleaning up.. "  >> test.log

kill -TERM $SERVER_PID
kill -TERM $CLIENT_PID
kill -TERM $LISTENER_PID
kill -TERM $TAIL_PID

rm test.log
rm tunnel
rm sender 
rm listener
