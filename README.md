# h2proxy

**Hardened HTTP/2 → HTTP/1.1 Streaming Proxy** with:

* Safe `_send_loop` for streaming
* Automatic retries for upstream requests
* Prometheus metrics
* ALPN (HTTP/2 over TLS)
* HTTP/2 server push
* Cloudflare IP whitelist via `ipset`

---

## Features

* **HTTP/2 Frontend**: Accepts incoming connections via TLS and HTTP/2.
* **HTTP/1.1 Upstream**: Proxies requests to an upstream HTTP/1.1 server.
* **Streaming**: Supports backpressure-aware streaming of large responses.
* **Security**:

  * Cloudflare IP whitelist (auto-refresh via `ipset`)
  * Strict transport security headers (`HSTS`, `X-Frame-Options`, `X-Content-Type-Options`)
* **Metrics**: Exposes Prometheus metrics on `METRICS_PORT` (default: `9100`).
* **Retries & Timeouts**: Automatic upstream retries and per-stream timeouts to avoid stalling.
* **HTTP/2 Push**: Handles `Link` headers to initiate server push streams.

---

## Requirements

* **System Packages**:

  ```bash
  sudo apt install python3-systemd ipset
  ```
* **Python Packages**:

  ```bash
  pip install twisted h2 prometheus-client
  ```

---

## Configuration

All configuration is at the top of the script:

| Variable                         | Default                               | Description                                  |
| -------------------------------- | ------------------------------------- | -------------------------------------------- |
| `CLOUDFLARE_IPS_URL`             | `"https://www.cloudflare.com/ips-v4"` | URL to fetch Cloudflare IPs                  |
| `IPSET_NAME`                     | `"cloudflare_whitelist"`              | Name of ipset for Cloudflare IPs             |
| `LISTEN_PORT`                    | `443`                                 | Port to listen for TLS/H2 connections        |
| `UPSTREAM_HOST`                  | `"127.0.0.1"`                         | Upstream HTTP/1.1 server host                |
| `UPSTREAM_PORT`                  | `8080`                                | Upstream server port                         |
| `IP_REFRESH_INTERVAL`            | `3600`                                | Interval (seconds) to refresh Cloudflare IPs |
| `CERT_FILE`                      | `"cert.pem"`                          | TLS certificate file                         |
| `KEY_FILE`                       | `"key.pem"`                           | TLS key file                                 |
| `MAX_CONCURRENT_STREAMS_DEFAULT` | `200`                                 | Max simultaneous HTTP/2 streams              |
| `MAX_BUFFER_PER_STREAM`          | `4*1024*1024`                         | Max bytes buffered per stream                |
| `CONNECTION_IDLE_TIMEOUT`        | `300`                                 | Close idle connections (seconds)             |
| `STREAM_INACTIVITY_TIMEOUT`      | `120`                                 | Reset inactive streams (seconds)             |
| `STREAM_BODY_TIMEOUT`            | `60`                                  | Max body download time per stream (seconds)  |
| `METRICS_PORT`                   | `9100`                                | Prometheus metrics port                      |

---

## Usage

1. **Generate TLS Certificate & Key** (self-signed example):

```bash
openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
```

2. **Run Proxy**:

```bash
sudo python3 h2proxy.py
```

> **Note:** Running on privileged ports (like 443) requires root or `CAP_NET_BIND_SERVICE`.

---

## Metrics

If `prometheus-client` is installed, the following metrics are exposed on `METRICS_PORT`:

* `h2proxy_requests_total`: Total proxied requests
* `h2proxy_active_streams`: Number of active streams
* `h2proxy_bytes_in_total`: Total bytes received from clients
* `h2proxy_bytes_out_total`: Total bytes sent to clients
* `h2proxy_streams_reset`: Number of streams reset due to errors/timeouts
* `h2proxy_ipset_refresh_count`: Times Cloudflare IPs were refreshed

---

## Security

* Only IPs in the Cloudflare whitelist can access the proxy.
* Sends HSTS, X-Frame-Options, X-Content-Type-Options, and Cache-Control headers.
* TLS 1.2+ only with secure ciphers (`ECDHE+AESGCM`).

---

## Signal Handling

The proxy handles:

* `SIGINT` (Ctrl+C)
* `SIGTERM`

and will gracefully clean up `ipset` and firewall rules before exit.

---

## License

This project is provided as-is without warranty. Use at your own risk.
