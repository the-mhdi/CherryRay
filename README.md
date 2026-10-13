# CherryRay

**CherryRay** is a multiplexed tunnel built on
[muxocket](https://github.com/the-mhdi/muxocket). It has two sides:

* **`server`** accepts muxocket sessions and forwards each named
  *channel* to a target (a TCP/UDP service, unix socket or raw IP host).
* **`client`** connects to a server and carries local traffic over one of
  those channels. The local side can be a listening socket or stdin/stdout.

One server can expose many services, each under its own channel name. The
connection between client and server (the **transport**) can be TCP, TLS,
UDP, raw IP or a two-way IP-spoofing raw transport that can pose as TCP.
Optional extras:

* end-to-end channel encryption with a post-quantum hybrid key exchange
* a local **SOCKS5 proxy** (`-listen socks5//…`): the server dials whatever
  destination each app asks for, within an allow/deny list
* **session pooling**: many local connections share a few long-lived sessions
* **WebSocket** and **HTTP/2** transports that pass CDNs and reverse proxies
* **browser TLS fingerprints** (uTLS: Chrome, Firefox, Safari, …)
* **probe fallback**: anything that isn't a CherryRay client is handed to a
  real web server
* **padding and timing obfuscation** of the stream (`-obfs`)
* HTTP header camouflage
* transparent session resumption when the network breaks

```
 local app ──► client ══════ transport (tcp / tls / ws / h2 / udp / ip / raw) ══════► server ──► target
              (-listen)        muxocket session, channel "ssh"                      (-channels ssh=…)
```

---

## Contents

1. [Building](#building)
2. [Quick start](#quick-start)
3. [Concepts](#concepts)
4. [Endpoints (`NET//ADDR`)](#endpoints-netaddr)
5. [Transports](#transports)
6. [TLS](#tls)
7. [End-to-end encryption and PSK](#end-to-end-encryption-and-psk)
8. [SOCKS5 proxy](#socks5-proxy)
9. [Session pooling (`-pool`)](#session-pooling--pool)
10. [WebSocket and HTTP/2 transports (`-ws`, `-h2`)](#websocket-and-http2-transports--ws--h2)
11. [Browser TLS fingerprints (`-fingerprint`)](#browser-tls-fingerprints--fingerprint)
12. [Probe fallback (`-fallback`)](#probe-fallback--fallback)
13. [Padding and timing obfuscation (`-obfs`)](#padding-and-timing-obfuscation--obfs)
14. [HTTP camouflage (`-http`)](#http-camouflage--http)
15. [Raw spoofing transport (`-raw`, `-faketcp`)](#raw-spoofing-transport--raw--faketcp)
16. [Datagram traffic](#datagram-traffic)
17. [Reliability, MTU and resumption](#reliability-mtu-and-resumption)
18. [Flag reference](#flag-reference)
19. [Wire protocol](#wire-protocol)
20. [Security notes](#security-notes)
21. [Performance notes](#performance-notes)
22. [Development](#development)

---

## Building

You need Go 1.26 or newer.

```sh
go mod tidy          # fetches muxocket, uTLS and x/net (see the note below)
go build ./cmd/CherryRayServer ./cmd/CherryRayClient
```

Dependencies: `golang.org/x/crypto` (BLAKE2b, ChaCha20-Poly1305),
`golang.org/x/sys` (raw sockets), `golang.org/x/net/http2` (`-h2`) and
`github.com/refraction-networking/utls` (`-fingerprint`, which pulls in
`klauspost/compress` and `go-brrr` for certificate compression).

## Quick start

**SSH over a plain UDP tunnel:**

```sh
# server
server -udp :7000 -channels ssh=tcp//127.0.0.1:22
# client: local port 2222 -> server's sshd
client -udp server:7000 -channel ssh -listen tcp//127.0.0.1:2222
ssh -p 2222 user@127.0.0.1
```

**SSH without a local port**, using CherryRayClient as a `ProxyCommand`:

```sh
ssh -o ProxyCommand='client -tcp server:7000 -channel ssh' user@host
```

**Several services on one server:**

```sh
server -tcp :7000 -channels ssh=tcp//127.0.0.1:22,web=tcp//127.0.0.1:443,dns=udp//1.1.1.1:53
client -tcp server:7000 -channel web -listen tcp//127.0.0.1:8443
client -tcp server:7000 -channel dns -listen udp//127.0.0.1:5353
```

**TLS with a pinned self-signed certificate and an encrypted channel:**

```sh
server -tcp :443 -tls -psk-file key.txt -channels ssh=tcp//127.0.0.1:22
#   log: TLS: clients connect with  -tls -tls-pin 3f9a…
client -tcp server:443 -tls -tls-pin 3f9a… -psk-file key.txt -channel ssh -listen tcp//127.0.0.1:2222
```

**web server camouflage(HTTP camouflage inside TLS):**

```sh
server -tcp :443 -tls -sni cdn.example.com -alpn h2,http/1.1 -http -http-path /live -channels ssh=tcp//127.0.0.1:22
client -tcp server:443 -tls -tls-pin … -sni cdn.example.com -alpn h2,http/1.1 -http -http-path /live -channel ssh -listen tcp//127.0.0.1:2222
```

**UDP transport** (muxocket supplies retransmission and ordering):

```sh
server -udp :7000 -channels dns -forward udp//1.1.1.1:53
client -udp server:7000 -channel dns -listen udp//127.0.0.1:5353
```

---

## Concepts

**Session.** A muxocket session is one authenticated transport connection
between client and server. The handshake is Ed25519-signed. The server
decides the window sizes, the frame size and whether reliability(packet retransmition and ARQ) is on.

**Channel.** A session carries channels, each named by a label of 1–6
letters or digits. Labels are case-insensitive, so `SSH` and `ssh` are the
same channel. muxocket has no "open channel" frame: both sides open the
same label. The server opens every channel in `-channels` for each session,
and the client opens the one named by `-channel`.

**(minimal limitation for now) One session per local connection.** Each connection accepted on the
client's `-listen` socket gets its own session: each local datagram peer for
packet listeners, or stdin/stdout without `-listen`. Connections never
block each other, flow control is per connection, and ending a connection
cleanly ends its session. The server closes a session once its channels are
finished, or after `-open-timeout` (default 15 s) if the client never opens
one.

**OPEN handshake.** muxocket do not support Open channel handshake by design, Many protocols have the server speak first (SSH, SMTP,
…), so the server can't wait for client data before dialing the target.
The client therefore starts every channel with a small OPEN request. It
carries:

* the **mode**: stream, or messages (datagrams)
* the **cipher**: none, or an AEAD suite plus a key share

The server answers with a status. It only dials the target after a valid
OPEN (and, with encryption, a successful handshake). If the dial fails, the
client gets a real error message instead of a silent EOF.

**Half-close.** When the local side finishes writing, the stream is
half-closed: EOF on one side becomes `CloseWrite` on the other. So
request/response exchanges like `printf 'GET /\r\n\r\n' | client …`
still get their full answer.

---

## Endpoints (`NET//ADDR`)

Local listeners (`client -listen`) and server targets (`-channels`,
`-forward`) use the same syntax. `NET://ADDR` also works.

| endpoint | meaning |
|---|---|
| `tcp//127.0.0.1:443`, `tcp6//[::1]:22` | TCP stream |
| `udp//1.1.1.1:53` | UDP datagrams |
| `unix///run/app.sock` | unix stream socket |
| `unixpacket///run/seq.sock` | unix `SOCK_SEQPACKET` (message boundaries kept, connection-oriented) |
| `unixgram///tmp/log.sock` | unix datagram socket |
| `ip4:253//10.0.0.2`, `ip6:253//fd00::2` | raw IP protocol 253 to/from a host (needs `CAP_NET_RAW`) |

`server -channels` takes `NAME[=NET//ADDR],…`. A channel without a
target uses `-forward`. A name may appear only once (case-insensitively).

---

## Transports

Exactly one transport is chosen on each side, and the two sides must match.

| transport | server | client | notes |
|---|---|---|---|
| TCP | `-tcp :7000` | `-tcp host:7000` | default reliability off (TCP already is reliable) |
| TLS | `-tcp :443 -tls` | `-tcp host:443 -tls …` | TLS 1.3 by default; see [TLS](#tls) |
| UDP | `-udp :7000` | `-udp host:7000` | muxocket reliability on; 4 MiB socket buffers |
| raw IP | `-ip ip4:253[@ADDR]` | `-ip ip4:253@SERVER` | IP protocol number of your choice; a 4-byte flow shim acts as a "port" |
| raw IP spoofing | `-raw …` | `-raw …` | forged source addresses both ways; optional fake TCP headers (`-faketcp`) |
| + HTTP camouflage | `-http` | `-http` | on top of TCP, TLS, or `-raw -faketcp` |
| + WebSocket | `-ws /path` | `-ws /path` | real RFC 6455 upgrade; on TCP or TLS; passes CDNs, see [below](#websocket-and-http2-transports--ws--h2) |
| + HTTP/2 | `-h2 /path` | `-h2 /path` | one streaming POST per connection; h2 over TLS or h2c |
| + obfuscation | `-obfs` | `-obfs` | padding, jitter and cover traffic on any stream transport |

Stream layers stack in this order, outermost first: TCP → TLS → one of
`-http` / `-ws` / `-h2` → `-obfs` → muxocket.

`-local IP` (client) fixes the transport's source address. That's needed
for raw IP when both ends run on one host.

---

## TLS

`-tls` wraps the `-tcp` transport in TLS.

**ALPN (`-alpn`, both sides).** The default is `muxtun/1`. Set a
comma-separated list in preference order, e.g. `-alpn h2,http/1.1`, so the
handshake looks like a browser talking to a web server. `-alpn none` sends
(client) or negotiates (server) no ALPN at all.

* **Client:** offers its list in the ClientHello.
* **Server:** picks the first entry of *its own* list that the client also
  offered.
* **No overlap:** if the client offers ALPN but none of the server's
  protocols, the handshake fails with `tls: no application protocol`. So
  set compatible lists on both sides.
* **ALPN on one side only:** a client that sends no ALPN, or a server
  configured with `none`, still connects; nothing is negotiated.
* The negotiated value doesn't change how the tunnel behaves. It is
  camouflage only.

```sh
server -tcp :443 -tls -sni cdn.example.com -alpn h2,http/1.1 -channels ssh=tcp//127.0.0.1:22
client -tcp server:443 -tls -tls-pin … -sni cdn.example.com -alpn h2,http/1.1 -channel ssh -listen tcp//127.0.0.1:2222
```

**Client — how the server is verified:**

* `-tls-pin HEX` trusts exactly that key. It works with self-signed
  certificates. Combined with `-tls-ca`, both the chain and the pin must
  match.
* `-tls-ca ca.pem` verifies against this CA instead of the system roots.
* `-tls-servername NAME` is the name to verify. The default is `-sni`, else
  the host from `-tcp`.
* `-sni NAME` is the name sent in the ClientHello. It can differ from the
  verified name (domain-fronting style). An IP address is never sent as SNI.
* `-tls-cert` / `-tls-key` provide a client certificate for mutual TLS.
* `-tls-insecure` skips verification (testing only).

---

## End-to-end encryption and PSK

TLS protects the transport hop only. `-encryption` encrypts each channel
from muxclient to muxserver, and it works on every transport (UDP, raw,
TCP, TLS).

* **Suites:** `chacha20-poly1305`, `xchacha20-poly1305`, `aes-128-gcm`,
  `aes-256-gcm`, or `none`.
  * Client: chooses one. The default is `chacha20-poly1305` if a PSK is set,
    else `none`.
  * Server: accepts a list (`-encryption all` or a comma list). The default
    is all suites, plus `none` only when no PSK is set.
* **Key exchange:** hybrid X25519 + ML-KEM-768, the same construction as
  TLS's `X25519MLKEM768`. Recorded traffic stays safe as long as either
  primitive holds, including against a future quantum computer.
* **Fresh keys per channel,** so every tunnelled connection has forward
  secrecy.
* **Authentication** comes from a pre-shared key: `-psk-file FILE` (one
  line, trailing newline ignored), `-psk VALUE` (visible in `ps`) or
  `$MUXTUN_PSK`. It is stretched with PBKDF2-SHA256 (200 000 rounds). Both
  sides prove they know it with a MAC over the handshake transcript. This
  stops man-in-the-middle attacks and unknown clients. A failed
  authentication drops the whole session. **Without a PSK the channel is
  encrypted but not authenticated** (the client logs a warning).
* **Records** are up to 16 KiB. The end of stream is an authenticated
  record, so an attacker can't cut a stream short with a forged FIN.

---

## SOCKS5 proxy

The client can act as a local SOCKS5 proxy. Each CONNECT becomes its own
channel, and the server dials the destination the app asked for, so
browsers and apps work without a channel per service.

```sh
# server: a socks5 channel; destinations limited by -socks-allow-dst
server -tcp :443 -tls -psk-file key.txt -channels px=socks5

# client: SOCKS5 on 127.0.0.1:1080, with username/password (RFC 1929)
client -tcp server:443 -tls -tls-pin HEX -psk-file key.txt -channel px \
       -listen socks5//127.0.0.1:1080 -socks-user me -socks-password secret -pool 4

curl --socks5-hostname me:secret@127.0.0.1:1080 https://example.com/
```

* `-forward socks5` (or `-channels px=socks5`) marks a channel as dynamic.
  Only SOCKS clients can use it, and a SOCKS client can only use such a
  channel.
* The address types IPv4, IPv6 and domain names all work. Names are resolved
  **on the server** (no DNS leak on the client side). Only CONNECT is
  supported; BIND and UDP ASSOCIATE get reply `07`.
* Without `-socks-user`, the proxy needs no auth. Then bind it to loopback
  only.
* Server errors map to SOCKS reply codes: forbidden → `02`, refused → `05`,
  host unreachable or timeout → `04`, network unreachable → `03`.

**`-socks-allow-dst`** is an ordered, comma-separated rule list. The first
match wins, and a destination that matches nothing is denied:

| rule | matches |
|---|---|
| `10.0.0.0/8`, `2001:db8::/32` | addresses in the CIDR |
| `1.2.3.4` | one address |
| `example.com` | exactly that name |
| `.example.com` | the name and all its subdomains |
| `…:443` (any rule) | only that port |
| `*` | everything |
| `!rule` | deny instead of allow |

Example: `-socks-allow-dst '!10.1.2.3,10.0.0.0/8:443,.example.com,!*'`.
Without the flag, the public internet is allowed but loopback, RFC 1918,
CGNAT, link-local (including cloud metadata `169.254.169.254`), ULA and
multicast are not, so a client can't reach the server's own network. Use
`-socks-allow-dst '*'` to allow everything. Every resolved address of a
name is checked and then dialed directly, so a DNS answer can't change
between the check and the connect.


## WebSocket and HTTP/2 transports (`-ws`, `-h2`)

Both put the muxocket stream inside traffic that HTTP infrastructure
understands. A CDN (Cloudflare and others) or a reverse proxy (nginx,
Caddy) can then sit in front of the server, so the server's address stays
hidden.

**WebSocket (`-ws /path`).** Every transport connection starts with a
genuine RFC 6455 upgrade (`Sec-WebSocket-Key`/`Accept`, version 13). Then
the stream travels in binary frames, masked from the client as the RFC
requires. The client waits for the `101` response before it sends data, so
proxies that don't forward early data work too. The server accepts only the
configured path. Anything else gets `404`/`400`, or goes to `-fallback`.

```sh
server -tcp 127.0.0.1:8443 -ws /chat -psk-file key.txt -channels px=socks5
# nginx/Caddy/CDN terminates TLS for cdn.example.com and proxies /chat to 127.0.0.1:8443
client -tcp cdn.example.com:443 -tls -sni cdn.example.com -ws /chat -fingerprint chrome \
       -alpn http/1.1 -psk-file key.txt -channel px -listen socks5//127.0.0.1:1080 -pool 4
```

**HTTP/2 (`-h2 /path`).** Every transport connection is a real HTTP/2
connection that carries one long POST, similar to gRPC streaming. The
request body is the client→server stream and the response body the
server→client stream. It uses TLS with ALPN `h2` (set automatically on both
ends unless you give `-alpn`), or cleartext h2c with prior knowledge
without `-tls`. Requests for other paths, and TLS clients that don't
negotiate `h2`, are reverse-proxied to `-fallback` or get `404`.

```sh
server -tcp :443 -tls -tls-cert cert.pem -tls-key key.pem -h2 /api/stream -fallback tcp//127.0.0.1:8080 -channels web=tcp//127.0.0.1:80
client -tcp example.com:443 -tls -h2 /api/stream -fingerprint chrome -channel web -listen tcp//127.0.0.1:8080
```

`-host NAME` (client) sets the `Host` header / `:authority` for both. The
default is `-sni`, else the host from `-tcp`. `-ws` and `-h2` can't be
combined with each other or with `-http`, but both work with `-tls`,
`-fingerprint`, `-obfs`, `-pool` and `-fallback`.

## Browser TLS fingerprints (`-fingerprint`)

Go's own TLS ClientHello is easy to recognise. Its cipher suites,
extensions and their order don't match any browser. `-fingerprint NAME`
(client, with `-tls`) sends a real browser's ClientHello using
[uTLS](https://github.com/refraction-networking/utls). This includes GREASE
values, key shares, extension order and ALPS:

| name | ClientHello of |
|---|---|
| `chrome` | current Chrome |
| `firefox` | current Firefox |
| `safari` | current Safari (macOS) |
| `ios` | Safari on iOS |
| `edge` | Edge |
| `random` | a randomized, browser-like hello (new per connection) |

Certificate verification, `-tls-pin`, `-tls-ca`, `-sni` and client
certificates work exactly as with plain `-tls`. The server needs nothing
special. Two things to keep in mind:

* The browser's ALPN list is replaced by `-alpn`. The default `muxtun/1`
  would stand out, so use the browser's own list on **both** ends:
  `-alpn h2,http/1.1` (with `-ws` use `-alpn http/1.1`; `-h2` sets `h2`
  automatically).
* The TLS versions offered come from the fingerprint. The fingerprints
  above all offer TLS 1.3. `random` is redrawn until it offers what
  `-tlsversion` requires.

## Probe fallback (`-fallback`)

Censors confirm a proxy by connecting to it themselves and seeing how it
reacts. With `-fallback NET//ADDR` (server, `-tcp` transports) every
connection is checked before muxocket sees it. The server reads the first
muxocket handshake message through all the stream layers (`-http`, `-ws`,
`-obfs`) and verifies its Ed25519 signature. Anything else (a browser, a
scanner, a replayed or corrupted header) is connected to the fallback
target along with every byte already read from it. The port then behaves
exactly like the web server behind it.

```sh
server -tcp :443 -tls -tls-cert cert.pem -tls-key key.pem -fallback tcp//127.0.0.1:8080 -channels ssh=tcp//127.0.0.1:22
curl https://example.com/      # → served by the web server on :8080
```

* While a connection is being checked, nothing it causes is sent (no
  `-http` response, no error page, no `-obfs` cover traffic). A probe only
  ever sees the fallback's bytes.
* With `-tls`, the fallback gets the **decrypted** stream, as with Trojan or
  Xray, so it is a plain HTTP server. With `-fallback` the server also
  accepts ALPN `http/1.1` (unless `-alpn` is given), because rejecting a
  browser's ALPN would give it away.
* A real client sends its handshake right away. A connection that sends
  something and then pauses for 750 ms (like a browser waiting for a
  response) is handed over at that point. A connection that sends nothing
  is closed after 10 s.
* `-ws`: a correct upgrade to the secret path gets `101`, and after that it
  can't be handed over any more. Every other request goes to the fallback.
  `-h2`: other paths are reverse-proxied per request (HTTP/1.1 to the
  fallback). Non-`h2` TLS clients and non-HTTP/2 cleartext clients are
  handed over whole.
* No client changes are needed.

## Padding and timing obfuscation (`-obfs`)

muxocket frames, the OPEN request and the key exchange have fixed sizes,
and length-pattern classifiers pick up on that. `-obfs` (on both ends, any
stream transport) wraps the stream in a light record layer:

```
dataLen(2) | padLen(1) | data | random padding
```

| flag | default | effect |
|---|---|---|
| `-obfs` | off | enable the record layer (must match on both ends) |
| `-obfs-pad MIN-MAX` | `0-255` | random padding per record; `0-0` turns padding off |
| `-obfs-jitter D` | `0` | up to D of random delay before each write |
| `-obfs-chaff D` | `0` (off) | send a cover-traffic record after D of idleness |

Records with `dataLen = 0` are chaff and are dropped by the receiver. Only
`-obfs` itself has to match. Padding, jitter and chaff apply to each
direction separately and may differ between the ends. This is
obfuscation, not secrecy: use `-tls` and/or `-encryption` for that. The
layer sits innermost, right under muxocket, inside `-http`/`-ws`/`-h2`.

## Session pooling (`-pool`)

By default every local connection gets its own session, and each one pays
for a transport connection, a TLS handshake and a muxocket handshake. With
`-pool N` the client keeps up to N long-lived sessions and opens one
**channel** per local connection on them. Nothing changes on the server:
every server supports pooled clients.

```sh
client -tcp server:443 -tls -tls-pin HEX -channel web -listen tcp//127.0.0.1:8080 -pool 4
```

* A new connection goes to the least busy session. When every session is
  busy and there are fewer than N, another one is dialed in the background.
* `-pool-idle D` (default `5m`) closes a session that has carried nothing
  for that long. The server closes pooled sessions that have been idle for
  10 minutes.
* It works with every transport, encryption (each channel still has its own
  key exchange) and SOCKS5. It needs `-listen`, because stdin/stdout is a
  single connection.
* Fewer handshakes mean lower latency for short connections, and fewer
  distinctive handshakes on the wire.

How it works: muxocket has no "open channel" frame, so the server opens a
control channel (`zz`) in every session. The client announces each new
slot label (`zz0000`, `zz0001`, …, never reused within a session) and the
server channel it wants on the control channel, then opens the slot and
sends the usual OPEN request. Channel names starting with `zz` are
therefore reserved.

## HTTP camouflage (`-http`)

This works like Xray's `http` header obfuscation for raw TCP. Each
transport connection starts with an ordinary-looking HTTP/1.1 request, and
the server sends back an HTTP response header. After that, the connection
carries the muxocket stream unchanged. This is camouflage against passive
DPI. It adds no secrecy or authentication, so combine it with `-tls` and/or
a PSK.

```
client -> server   GET /live HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0 …\r\n…\r\n\r\n  <muxocket>
server -> client   HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n…\r\n\r\n             <muxocket>
```

It works with `-tcp`, `-tcp -tls` (the header is inside TLS) and
`-raw -faketcp`. The flag is needed on both sides.

```sh
server -tcp :80 -http -http-host cdn.example.com -http-path /video,/live \
          -http-header "Server: nginx" -channels ssh=tcp//127.0.0.1:22
client -tcp server:80 -http -http-host cdn.example.com -http-path /video \
          -http-header "User-Agent: curl/8.5.0" -channel ssh -listen tcp//127.0.0.1:2222
```

| flag | client | server |
|---|---|---|
| `-http` | enable | enable (clients must send a matching header) |
| `-http-host` | Host value(s), one picked at random per connection. Default: `-sni`, else the server host (`:port` kept unless 80/443) | accepted Host values (default: any). Case-insensitive; the port is ignored |
| `-http-path` | path(s), one picked at random per connection (default `/`) | accepted paths (default: any). The query string is ignored unless the entry contains `?` |
| `-http-method` | method (default `GET`) | only accept this method (default: any) |
| `-http-header "Name: value"` | extra request header, repeatable. Replaces a default with the same name; `"Name:"` removes it | the same, for response headers |
| `-http-status` | – | response status, 2xx/3xx (default `200 OK`) |

**Default headers:**

* **Request:** Chrome-like `User-Agent`, `Accept`,
  `Accept-Encoding: gzip, deflate`, `Accept-Language`,
  `Connection: keep-alive`, `Pragma: no-cache`.
* **Response:** `Content-Type: application/octet-stream`,
  `Transfer-Encoding: chunked`, `Connection: keep-alive`,
  `Pragma: no-cache`, `Date`.

**How it behaves:**

* **Every connection gets a header,** including muxocket's automatic
  redials when the session resumes.
* **0-RTT.** The client writes the request and starts the muxocket
  handshake straight away, without waiting for the response. It removes the
  response from the stream when it arrives. A 4xx/5xx answer is reported as
  an error.
* **The server never blocks in `Accept`.** It reads and checks the request
  lazily, inside muxocket's handshake and its timeout. A silent or slow
  client doesn't hold up others.
* **Mismatches are answered like a web server would:** `400`, `404`, `405`
  or `431`, then the connection is closed. Headers are limited to 8 KiB.
* **With `-raw -faketcp`** there is no byte stream, so the header goes at
  the start of the crafted TCP payload:
  * The client puts the request on every packet until the server first
    answers. This covers lost handshake packets.
  * The server puts the response on its packets until the client sends a
    packet without the request.
  * The server drops packets from flows that never sent a valid request.
  * A header is only added if the packet still fits the link MTU
    (`-mtu` on the server, else 1500).

---

## Raw spoofing transport (`-raw`, `-faketcp`)

This is a two-way IP-spoofing tunnel. Every packet either side sends carries
a **forged source address**, and each side only accepts packets whose
source is on its whitelist. It runs on Linux only, IPv4 only, and needs
`CAP_NET_RAW`.

Addressing is fixed in advance, because a spoofed source can't be answered
by reflection:

| | client | server |
|---|---|---|
| real IP | the host's own | `-raw-peer` on the client |
| `-raw-peer` | server's real IP | client's real IP |
| `-spoof-src` | forged source CS | forged source SS |
| `-accept-src` | SS (peer's forgery) | CS (peer's forgery) |

```sh
server -raw -spoof-src 77.0.0.1 -raw-peer CLIENT_IP -accept-src 88.0.0.2 \
          -psk-file key.txt -channels web=tcp//127.0.0.1:8080
client -raw -spoof-src 88.0.0.2 -raw-peer SERVER_IP -accept-src 77.0.0.1 \
          -psk-file key.txt -channel web -listen tcp//127.0.0.1:8080
```

```sh
server -raw -spoof-src 77.0.0.1 -raw-peer CLIENT_IP -faketcp -faketcp-sport 443 \
         -faketcp-dport 10547 -faketcp-seq 9595955 -channels bbb=tcp//127.0.0.1:22

client -raw -spoof-src 88.0.0.2 -raw-peer SERVER_IP -faketcp -faketcp-sport 10547 \
          -faketcp-dport 443 -faketcp-seq 9595955 -channel spoof  -listen tcp//0.0.0.0:2222
```

* **Plain raw:** the payload rides directly in IP packets of `-raw-proto`
  (default 253; 6 is not allowed).
* **`-faketcp`:** the payload rides inside crafted TCP segments, so the
  flow looks like ordinary TCP. Use `-faketcp-sport` and `-faketcp-dport`
  (mirrored on the two sides) and
  `-faketcp-flags` (default `PSH,ACK`). `-faketcp-seq` sets the starting
  sequence number (default random). `-faketcp-seq-incr payload|packet|none`
  sets how it advances; `payload` behaves like real TCP. Packets have Don't
  Fragment set and valid IP and TCP checksums.
* **Flow shim.** A 4-byte shim (`'M'`, direction, 16-bit flow ID) tells
  sessions apart. The direction byte stops a host from parsing its own
  packets.
* **Untrusted path.** Spoofed packets travel over paths you don't control,
  so use a PSK.

---

## Datagram traffic (Packet Based protocols)

* **Packet listeners** (`udp//`, `unixgram//`, `ip4:N//`): every local
  peer address becomes a *flow* with its own session. Datagrams that
  arrive while the session is being set up are queued (excess is dropped,
  like a router would). A flow ends after `-idle` (default 2 min) without
  traffic.
* **Framing.** Inside the channel, datagrams are framed as
  `len(2) | payload`, so message boundaries survive the stream. `unixpacket`
  keeps boundaries as well; zero-length messages can't be carried.
* **The server's target decides the wire format.** Message targets (udp,
  unixgram, unixpacket, ip) exchange framed messages; stream targets get raw
  bytes. A datagram client talking to a TCP target therefore sends
  DNS-over-TCP style length-prefixed messages, which is exactly what a TCP
  DNS server expects.
* **Half-close.** When the client side half-closes (e.g.
  `printf query | client …`), the server keeps relaying replies for 2 s.

---

## Reliability, MTU and resumption

* **`-reliable auto|on|off`** (server). The server decides and the client
  follows. `auto` turns muxocket's retransmission and ordering on for
  `-udp`/`-ip`/`-raw` and off for `-tcp`. Turning it off on a lossy
  datagram transport corrupts or stalls channels (a warning is logged).
* **`-mtu`** (server) is the maximum IP payload for datagram transports.
  The defaults avoid fragmentation on a 1500-byte link:
  * UDP: 1472 (IPv4) / 1452 (IPv6)
  * raw IP: 1480 / 1460, minus the 4-byte shim
  * `-raw`: 1500 minus the IP, TCP and shim headers

  The client learns the frame size from the server's handshake.
* **Resumption.** If the transport breaks (server socket restart, NAT
  rebinding, roaming client), muxclient redials and resumes the session
  through muxocket's signed resumption (session ID plus an increasing
  nonce). Open channels continue without data loss, and the server accepts
  the migrated session transparently.
* **Retries.** On datagram transports the initial handshake is tried three
  times within `-dial-timeout`.

---

## Flag reference

### Server

```
usage: server (-tcp ADDR | -udp ADDR | -ip ip4:PROTO[@ADDR] | -raw …) [-channels LIST] [-forward NET//ADDR] [flags]
```

| flag | default | description |
|---|---|---|
| **transport** | | |
| `-tcp host:port` | | listen on TCP |
| `-udp host:port` | | listen on UDP |
| `-ip ip4:PROTO[@ADDR]` | | listen on raw IP (`ip6:` too) |
| `-mtu N` | per transport | max IP payload for datagram transports |
| `-reliable auto\|on\|off` | `auto` | retransmission/ordering |
| **channels** | | |
| `-channels NAME[=NET//ADDR],…` | `tunnel` | channels opened in every session |
| `-forward NET//ADDR` | | default target for channels without one; `socks5` for SOCKS clients |
| `-socks-allow-dst RULES` | public internet only | destinations socks5 channels may reach (see [SOCKS5](#socks5-proxy)) |
| `-fallback NET//ADDR` | | hand non-CherryRay connections to this web server |
| `-dial-timeout D` | `10s` | timeout for dialing a target |
| `-open-timeout D` | `15s` | close sessions that open no channel (also bounds the key exchange) |
| `-idle D` | `2m` | end idle datagram flows |
| **encryption** | | |
| `-encryption LIST` | all (+none without PSK) | accepted channel ciphers |
| `-psk-file F` / `-psk V` / `$MUXTUN_PSK` | | pre-shared key |
| **TLS** | | |
| `-tls` | off | TLS on `-tcp` |
| `-tls-cert F` / `-tls-key F` | self-signed | certificate (PEM) |
| `-tls-client-ca F` | | require client certificates (mTLS) |
| `-tlsversion V` | `1.3` | `1.1`/`1.2`/`1.3` or `MIN-MAX` |
| `-sni NAMES` | | accepted SNI names; added to a generated certificate |
| `-alpn LIST` | `muxtun/1` (`h2` with `-h2`; `+http/1.1` with `-fallback`) | accepted ALPN protocols |
| **WebSocket / HTTP/2** | | |
| `-ws PATH` | | WebSocket transport at this path |
| `-h2 PATH` | | HTTP/2 transport at this path |
| **obfuscation** | | |
| `-obfs`, `-obfs-pad`, `-obfs-jitter`, `-obfs-chaff` | off | see [`-obfs`](#padding-and-timing-obfuscation--obfs) |
| **HTTP camouflage** | | |
| `-http` | off | require/answer fake HTTP headers |
| `-http-host NAMES` | any | accepted Host values |
| `-http-path PATHS` | any | accepted paths |
| `-http-method M` | any | accepted method |
| `-http-header "N: V"` | | response header (repeatable) |
| `-http-status S` | `200 OK` | response status |
| **raw spoofing** | | |
| `-raw` | off | spoofing transport |
| `-spoof-src IP` | | forged source of our packets |
| `-raw-peer IP` | | the client's real IP |
| `-accept-src IPs` | any | accepted (forged) sources |
| `-raw-proto N` | `253` | IP protocol (plain raw) |
| `-faketcp` | off | crafted TCP segments |
| `-faketcp-sport P` / `-faketcp-dport P` | | our / the client's TCP port |
| `-faketcp-flags F` | `PSH,ACK` | TCP flags |
| `-faketcp-seq N` | random | starting sequence number |
| `-faketcp-seq-incr M` | `payload` | `payload`, `packet` or `none` |
| `-v` | off | verbose logging |

### Client

```
usage: client (-tcp ADDR | -udp ADDR | -ip ip4:PROTO@ADDR | -raw …) [-channel NAME] [-listen NET//ADDR] [flags]
```

| flag | default | description |
|---|---|---|
| **transport** | | |
| `-tcp host:port` / `-udp host:port` / `-ip ip4:PROTO@ADDR` | | server address |
| `-local IP` | | local source IP for the transport |
| `-dial-timeout D` | `10s` | connect + handshake + open timeout |
| **local side** | | |
| `-channel NAME` | `tunnel` | server channel to use |
| `-listen NET//ADDR` | stdin/stdout | local listener; `socks5//ADDR` for a SOCKS5 proxy |
| `-socks-user U` / `-socks-password P` | no auth | SOCKS5 username/password (RFC 1929) |
| `-pool N` | `0` (off) | share up to N sessions between local connections |
| `-pool-idle D` | `5m` | close a pooled session idle this long |
| `-idle D` | `2m` | end idle datagram flows |
| **encryption** | | |
| `-encryption SUITE` | chacha20-poly1305 with PSK, else none | channel cipher |
| `-psk-file F` / `-psk V` / `$MUXTUN_PSK` | | pre-shared key (must match the server) |
| **TLS** | | |
| `-tls` | off | TLS on `-tcp` |
| `-tls-pin HEX` | | trust exactly this key |
| `-tls-ca F` | system roots | CA for verification |
| `-tls-servername N` | `-sni`, else host | name to verify |
| `-sni N` | `-tls-servername`, else host | name in the ClientHello |
| `-tls-cert F` / `-tls-key F` | | client certificate (mTLS) |
| `-tlsversion V` | `1.3` | version or range |
| `-tls-insecure` | off | don't verify (testing only) |
| `-alpn LIST` | `muxtun/1` (`h2` with `-h2`) | ALPN protocols offered |
| `-fingerprint NAME` | Go's own | browser ClientHello: `chrome`, `firefox`, `safari`, `ios`, `edge`, `random` |
| **WebSocket / HTTP/2** | | |
| `-ws PATH` | | WebSocket transport at this path |
| `-h2 PATH` | | HTTP/2 transport at this path |
| `-host NAME` | `-sni`, else server host | Host / `:authority` for `-ws`/`-h2` |
| **obfuscation** | | |
| `-obfs`, `-obfs-pad`, `-obfs-jitter`, `-obfs-chaff` | off | see [`-obfs`](#padding-and-timing-obfuscation--obfs) |
| **HTTP camouflage** | | |
| `-http` | off | send fake HTTP headers |
| `-http-host NAMES` | `-sni`, else server host | Host header candidates |
| `-http-path PATHS` | `/` | path candidates |
| `-http-method M` | `GET` | method |
| `-http-header "N: V"` | | request header (repeatable) |
| **raw spoofing** | | the same `-raw`/`-spoof-src`/`-raw-peer`/`-accept-src`/`-raw-proto`/`-faketcp*` flags; `-raw-peer` is the server's real IP and `-faketcp-dport` the server's port |
| `-v` | off | verbose logging |

Flags that only make sense together are checked. For example, `-tls-*`
and `-fingerprint` need `-tls`, `-http-*` needs `-http`, `-faketcp` needs
`-raw`, `-http` over `-raw` needs `-faketcp`, `-socks-*` needs a socks5
listener or channel, `-pool-idle` needs `-pool`, and `-ws`/`-h2`/`-http`
exclude each other.

---

## Wire protocol

Layers, outermost first (each optional layer only when enabled):

```
[IP + fake TCP + flow shim]  or  TCP [+ TLS (Go or browser ClientHello)]  or  UDP  or  IP + flow shim
  [HTTP header (first bytes / first packets)  |  WebSocket frames  |  HTTP/2 POST stream]
    [-obfs records   dataLen(2) padLen(1) data padding]
      muxocket frames   length(4) flag(1) channelID(4) offset(8) payload
        [pool control channel "zz": slotLen(1) slot nameLen(1) name]
        OPEN request / status   (mode 2 = SOCKS CONNECT: + len(1) "host:port")
        [encryption handshake, then AEAD records]
          your application's bytes (or len(2)-framed datagrams)
```

**OPEN** (first bytes of every channel, client to server):

```
'M' 'X' 'T' version(1)=2 mode(1) cipher(1) [client key share]
mode: 0 stream, 1 messages
```

**Status** (server to client): `code(1) msgLen(1) msg`. Codes: 0 OK,
1 dial failed, 2 bad request, 3 forbidden (cipher not accepted). With
encryption, the final status is the first encrypted record.

**Encryption handshake:**

```
client -> server  OPEN(cipher) | x25519 pub(32) | ML-KEM-768 encaps key(1184) | random(32)
server -> client  status "accepted"
server -> client  x25519 pub(32) | ML-KEM ciphertext(1088) | random(32) | server MAC(32)
client -> server  client MAC(32)
record            len(2) | AEAD(type(1) | data)    nonce = per-direction counter, len = AD
```

**Raw-IP flow shim:** `'M' dir flowID(2)`. `dir` is `'X'` for client to
server and `'Y'` for server to client.

---

## Security notes

* **muxocket's own handshake** is signed and protects session identity and
  resumption. It does **not** encrypt traffic. Use `-tls` for the transport
  hop and/or `-encryption` with a PSK end to end.
* **With `-encryption`,** the muxocket frame headers (channel IDs, offsets,
  sizes) stay visible. Payload, status messages and end of stream are
  protected.
* **`-http` is camouflage only.** Use it with TLS if the content of the
  stream must not look random.
* **Self-signed certificates change on every server start.** Pin a
  certificate you load with `-tls-cert`/`-tls-key` if clients must keep
  working across restarts.
* **Keep the PSK out of `ps`:** prefer `-psk-file` or `$MUXTUN_PSK` over
  `-psk`.
* **Use a PSK with `-raw` traffic:** the forged addresses are only a
  filter, not authentication.
* **An open SOCKS5 proxy is an open relay.** Bind `-listen socks5//` to
  loopback or set `-socks-user`/`-socks-password`, and keep the server's
  `-socks-allow-dst` as narrow as you can. The default already blocks the
  server's own and private networks.
* **`-ws`/`-h2` paths are not secrets on their own.** Anyone who learns
  the path can complete the upgrade. Authentication still comes from
  muxocket's handshake and the PSK.
* **`-obfs` and `-fingerprint` resist classification, not decryption.**
  Neither one adds secrecy.

---

## Performance notes

* **Stream relaying is copy-light.** It uses `io.CopyBuffer`, so muxocket's
  `Channel.ReadFrom`/`WriteTo` read straight into and write straight out of
  the channel buffers. With encryption, `SecureConn.ReadFrom`/`WriteTo`
  seal and open records in place. Datagram framing writes the length header
  in place without copying the payload.
* **Each local connection gets its own session by default.** That gives
  isolation and clean shutdown, but every new connection pays for a
  transport handshake (plus TLS and the key exchange if enabled). For many
  short connections (browsers, SOCKS5), use `-pool N`.
* **Transport cost** : plain TCP > `-obfs` > `-tls` > `-tls + -ws` >  `-tls + -h2`
---

Layout:

```
cmd/CherryRayServer  server: transports, channel specs, pool control, OPEN handling, forwarding
cmd/CherryRayClient  client: listeners, SOCKS5, session pool, flows, connect/resume
internal/tunnel
  endpoint.go      NET//ADDR endpoints, transports, dialers
  open.go          OPEN request / status
  secure.go        end-to-end encryption (hybrid KEX, AEAD records)
  tls.go           TLS configs, pins, SNI rules, self-signed certificates
  http.go          -http camouflage (stream wrappers, flags)
  ws.go            -ws WebSocket transport (upgrade, framing)
  h2.go            -h2 HTTP/2 transport (client stream, server listener, fallback proxy)
  utls.go          -fingerprint browser ClientHellos (uTLS)
  fallback.go      -fallback probe vetting and replay
  obfs.go          -obfs padding / jitter / chaff record layer
  pool.go          -pool control-channel protocol and slot labels
  socks.go         SOCKS5 server handshake (client side)
  socks_policy.go  -socks-allow-dst rules and checked dialing
  pipe.go          stream / message / datagram pumps
  ipflow.go        raw-IP flow shim
  spoof*.go        -raw spoofing transport and fake TCP (Linux)
```

Raw-socket paths need root and are covered by codec and state unit tests.
The stream transports, TLS, HTTP camouflage, encryption and resumption are
tested end to end over loopback.