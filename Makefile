build:
	mkdir build
	go mod download
	go build -o build/server server/server.go
	go build -o build/client client/client.go
	cp server/config-example.json build/server-config-example.json
	cp client/config-example.json build/client-config-example.json

clean:
	go clean
	rm -r build