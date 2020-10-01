FROM golang:1.15.2-alpine as build

ARG GOARCH=
ARG GO_BUILD_ARGS=

# Threshold has its own certificates -- it doesn't need the public internet ones
# RUN apk add --update --no-cache ca-certificates git
RUN mkdir /build
WORKDIR /build
COPY . .

RUN go build -v $GO_BUILD_ARGS -o /build/threshold main.go

FROM alpine
WORKDIR /threshold

# COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /build/threshold /threshold/threshold
RUN mkdir -p /threshold/config

# NOTE: the user will have to mount the config file & any required TLS certs/keys into /opt/threshold/
# as well as override the default command (-mode server)

ENTRYPOINT ["/threshold/threshold"]
CMD ["-mode", "server"]