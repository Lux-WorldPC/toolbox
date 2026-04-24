# secret-proxy

Backend for four tools of [@lwpc/toolbox](https://github.com/Lux-WorldPC/toolbox):

- **Secure Message** — E2E encrypted, self-destructing messages
- **Domain Checkup** — DNS, email security, TLS, mail client config
- **What's My IP** — public IP lookup + RIPE enrichment
- **Email Header Analyzer** — the backend only handles the optional
  "receive report by email" endpoint; the analysis itself is 100% client-side

**Zero NPM dependency.** Pure Node.js stdlib. Requires Node ≥ 20.6 (uses
`--env-file` for built-in `.env` loading).

## Setup

```bash
cd backend/secret-proxy
cp .env.example .env
# Edit .env — at minimum set TURNSTILE_SECRET

# Start
npm start
# or: node --env-file=.env server.js
```

The server listens on `127.0.0.1:3100` by default. Put nginx / Caddy /
Cloudflare in front and route the endpoints listed below to it.

## Endpoints

### Secure Message

| Method | Path | Purpose |
|---|---|---|
| POST | `/secret/api/create` | Store an E2E-encrypted blob. Returns `{id, expiresAt}`. |
| POST | `/secret/api/reveal` | Return the blob and delete the file. |

The server **cannot decrypt** stored blobs — the key lives in the URL fragment
client-side. See `frontend/secret/secret-tools.js` for the client protocol.

### Domain Checkup

All under `/api/domain-tools/`. Each returns JSON.

| Path | Purpose |
|---|---|
| `/ip-info?ip=X` | RIPE Stat: netname, org, ASN, CIDR, country |
| `/ssl?host=X&port=443` | TLS certificate via `tls.connect()` |
| `/whois?domain=X` | Simplified WHOIS via system `whois` binary |
| `/detect?url=X` | CMS / platform fingerprint |
| `/mta-sts?domain=X` | Fetch `mta-sts.{domain}/.well-known/mta-sts.txt` + parse |
| `/autodiscover?domain=X` | Microsoft Autodiscover (CNAME + HTTP probe) |
| `/autoconfig?domain=X` | Thunderbird autoconfig XML |

### What's My IP

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/myip?ip=X` | Reverse DNS + RIPE Stat enrichment |

### Email Header Analyzer (optional)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/email-report` | Send the analysis report by email via Mailgun |

The endpoint is disabled automatically if `MAILGUN_API_KEY` / `MAILGUN_DOMAIN`
are not set.

## Security

- **Listens on `127.0.0.1`** — configure a reverse proxy (nginx / Caddy) to
  expose it publicly. The proxy should forward `X-Forwarded-For`.
- **Rate limits** — 20 req/min create, 60 req/min reveal and domain-tools,
  10 req/min email-report (in-memory, per-IP).
- **Daily create quota** — 12/IP (reset at UTC midnight). Bypass via
  `SCRT_WHITELIST_IPS`.
- **Cloudflare Turnstile** — required on create. Skipped automatically when
  the request comes from `127.0.0.1` with no `X-Forwarded-For`.
- **Opaque storage** — stored ciphertext is never decryptable by the server.
  Hourly cleanup sweeps expired entries.

## Configuration

See [.env.example](.env.example) for the full list of environment variables.
The only required key is `TURNSTILE_SECRET`.

## Frontend pairing

The corresponding frontends live in `frontend/{secret,domain,myip,email-headers}/`.
They call this backend at the same origin by default. To point them at a
different host (useful for split frontend/backend deployments):

```html
<script>window.LWPC_API_BASE = 'https://api.example.com';</script>
<script src="secret-tools.js"></script>
```

## License

MIT — see [LICENSE](../../LICENSE).
