FROM alpine:3.8

WORKDIR /tunnel

COPY tunnel /tunnel

RUN echo " \
{ \
  \"DebugLog\": false, \
  \"TunnelControlPort\": 9056, \
  \"ManagementPort\":  9057 \
} \
" > /tunnel/config.json

ENTRYPOINT [ "/tunnel/tunnel" ]
CMD ["-mode", "server"]

