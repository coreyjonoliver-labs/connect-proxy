FROM docker.io/library/alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# A minimal HTTP CONNECT proxy for a VPN-gateway sidecar: CONNECT to
# :443/:80 only, global-unicast IPv4 targets only, non-root, no per-request
# logging. See proxy.py for the full contract.
ARG PROXY_VERSION=1.0.0

RUN addgroup -g 1000 proxy \
 && adduser -D -H -u 1000 -G proxy -s /sbin/nologin proxy \
 && apk add --no-cache python3 \
 && [ "$(id -u proxy)" = "1000" ] \
 && python3 -c 'import ipaddress, select, socket, threading'

COPY --chmod=0444 proxy.py /app/proxy.py

USER 1000:1000

ENTRYPOINT ["python3", "/app/proxy.py"]
