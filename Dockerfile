FROM golang:1.15.2-alpine as build

ARG GOARCH=amd64
ARG GO_BUILD_ARGS=

RUN apk add --update --no-cache ca-certificates git
RUN mkdir /build
WORKDIR /build
COPY . .

RUN go build -v $GO_BUILD_ARGS -o /build/threshold main.go

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /build/threshold /threshold

# NOTE: the user will have to mount the config file & any required TLS certs/keys
# as well as override the default command (-mode server)

ENTRYPOINT ["/threshold"]
CMD ["-mode", "server"]