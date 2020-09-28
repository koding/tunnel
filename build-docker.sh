#!/bin/bash -e

docker build --build-arg "GOARCH=amd64" -t sequentialread/threshold:0.0.0-amd64 .
docker build --build-arg "GOARCH=arm" -t sequentialread/threshold:0.0.0-arm .

docker push sequentialread/threshold:0.0.0-amd64
docker push sequentialread/threshold:0.0.0-arm

export DOCKER_CLI_EXPERIMENTAL=enabled

docker manifest create sequentialread/threshold:0.0.0 \
  sequentialread/threshold:0.0.0-amd64 \
  sequentialread/threshold:0.0.0-arm

docker manifest annotate --arch amd64 sequentialread/threshold:0.0.0 sequentialread/threshold:0.0.0-amd64
docker manifest annotate --arch arm sequentialread/threshold:0.0.0 sequentialread/threshold:0.0.0-arm

docker manifest push sequentialread/threshold:0.0.0