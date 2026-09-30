# connect-proxy

A minimal HTTP `CONNECT` proxy, built to run as a non-root sidecar inside a
VPN-gateway pod so that a browser elsewhere can use the pod's tunnel as its
exit without being able to reach anything private through it.

- `CONNECT host:443` and `CONNECT host:80` only. Plain proxied requests
  (`GET http://…`) are refused, so it never parses or rewrites a request body.
- Every target hostname is resolved with the container's own resolver, and
  every address it resolves to must be a global-unicast IPv4 address —
  loopback, private (RFC 1918), link-local, carrier-grade NAT, multicast,
  reserved and all IPv6 answers refuse the whole name. The connection is
  made to the vetted address, never by re-resolving.
- No authentication: who may reach the listener is the surrounding network
  policy's job.
- Bounded request size, concurrent connections and idle time.
- Logs no hostnames, ports or clients — only startup and periodic counts.

Runs as uid 1000 with a read-only root filesystem and no capabilities.
Configuration by environment: `LISTEN` (default `0.0.0.0:8888`),
`MAX_CONNECTIONS` (64), `IDLE_TIMEOUT` seconds (300), `CONNECT_TIMEOUT`
seconds (15).

The image is published to `ghcr.io/coreyjonoliver-labs/connect-proxy:<version>`
with a GitHub build-provenance attestation. `python3 selftest.py` exercises
the refusal paths, the address policy and the relay without any network.
