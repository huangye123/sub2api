# codex-tls-proxy

`codex-tls-proxy` is a local HTTP CONNECT proxy for capturing the TLS ClientHello
sent by Codex. It extracts the fields used by Sub2API TLS fingerprint profiles and
writes an importable JSON payload.

The proxy does not decrypt HTTPS traffic. It only reads the public TLS handshake
bytes before forwarding them to the requested upstream host.

## Build

```powershell
cd backend
go build -o ..\bin\codex-tls-proxy.exe .\cmd\codex-tls-proxy
```

## Capture Codex

Start the proxy:

```powershell
.\bin\codex-tls-proxy.exe -listen 127.0.0.1:18080 -out codex-tls-profile.json -name codex_windows
```

Run Codex through it in another terminal:

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:18080"
codex
```

The generated `codex-tls-profile.json` can be posted to:

```text
POST /api/v1/admin/tls-fingerprint-profiles
```

To paste into the existing Sub2API admin TLS fingerprint profile dialog, write
YAML instead:

```powershell
.\bin\codex-tls-proxy.exe -format yaml -out codex-tls-profile.yaml -name codex_windows
```

## Import Directly

Set an admin JWT and pass the Sub2API URL:

```powershell
$env:SUB2API_ADMIN_TOKEN = "<admin-jwt>"
.\bin\codex-tls-proxy.exe -sub2api-url http://127.0.0.1:8080 -name codex_windows
```

You can generate an admin JWT from this repository with:

```powershell
cd backend
go run .\cmd\jwtgen
```

## Useful Flags

- `-match api.openai.com,chatgpt.com`: only capture matching CONNECT hosts or SNI values.
- `-format yaml`: write YAML that can be pasted into the admin dialog parser.
- `-out -`: print the JSON payload to stdout.
- `-once=false`: keep capturing additional matching ClientHello messages.
- `-v`: log skipped and malformed connections.
