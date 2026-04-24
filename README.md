# toolbox

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live demo](https://img.shields.io/badge/live_demo-lwpc.lu%2Ftoolbox-3d5394)](https://lwpc.lu/lb/toolbox/)
[![Tools](https://img.shields.io/badge/tools-6%2F6_frontends_published-brightgreen)](#available-tools)

Open-source IT utilities from [lwpc.lu](https://lwpc.lu).

This repository contains the source code of the utilities available at
[lwpc.lu/toolbox/](https://lwpc.lu/lb/toolbox/). Everything runs client-side
unless otherwise specified. No data leaves the browser for tools marked
**100% local**.

Published under the MIT License so anyone can audit, reuse, adapt, or self-host.

**▶ [Try the live demo on lwpc.lu/toolbox/](https://lwpc.lu/lb/toolbox/)**

## Available tools

| Tool | Frontend | Backend | Live demo |
|---|---|---|---|
| Password Generator (Classic + Passphrase) | ✅ | n/a (100% local) | [/toolbox/password/](https://lwpc.lu/lb/toolbox/password/) |
| Secure Message (E2E encrypted, self-destructing) | ✅ | ⏳ planned | [/toolbox/secret/](https://lwpc.lu/lb/toolbox/secret/) |
| Domain Checkup (SPF/DKIM/DMARC/DNSSEC/TLS…) | ✅ | ⏳ planned | [/toolbox/domain/](https://lwpc.lu/lb/toolbox/domain/) |
| What's My IP (v4/v6, rDNS, ASN, country) | ✅ | ⏳ planned | [/toolbox/myip/](https://lwpc.lu/lb/toolbox/myip/) |
| Email Header Analyzer (spoofing + BEC detection) | ✅ | ⏳ planned | [/toolbox/email-headers/](https://lwpc.lu/lb/toolbox/email-headers/) |
| QR Code Generator (CLI, Python) | ✅ | n/a | — |

All 6 **frontends** are now published. Tools that need a backend expose their
endpoint contract under `backend/` (published after internal review). The
frontends work today against the live demo endpoints at `lwpc.lu` or against
your own backend via `window.LWPC_API_BASE`.

## Layout

```
frontend/              Client-side tools (HTML + JS + CSS, no build step)
  shared.css             Common primitives (body, buttons, form) — loaded by all tools
  password/              Password Generator — 100% local, no backend
  secret/                Secure Message (create + view/ reveal page)
  domain/                Domain Checkup
  myip/                  What's My IP
  email-headers/         Email Header Analyzer (spoofing + BEC)
backend/               Server-side components (published after review)
tools/                 Standalone utilities
  qr/                    Python QR code generator (CLI)
```

## Run locally

```bash
git clone https://github.com/Lux-WorldPC/toolbox.git
cd toolbox
python3 -m http.server 8000
# open http://localhost:8000/frontend/password/
#      http://localhost:8000/frontend/secret/
#      http://localhost:8000/frontend/domain/
#      http://localhost:8000/frontend/myip/
#      http://localhost:8000/frontend/email-headers/
```

**Password Generator** and **QR Code Generator** are 100% local — they work
offline and need no backend.

The other four tools expect a small backend exposing these endpoints:

| Tool | Endpoint |
|---|---|
| Secure Message | `POST /secret/api/create`, `POST /secret/api/reveal` |
| Domain Checkup | `GET /api/domain-tools/{ip-info,ssl,whois,detect,mta-sts,autodiscover,autoconfig}` |
| What's My IP | `GET /api/myip?ip=X` |
| Email Header Analyzer | `POST /api/email-report` (optional — only for "receive report by email") |

### Pointing the frontend at your own backend

By default, all frontends call `/api/...` on the same origin. To target a
different backend, set `window.LWPC_API_BASE` **before** loading the tool's JS:

```html
<script>window.LWPC_API_BASE = 'https://api.example.com';</script>
<script src="myip.js"></script>
```

### QR Code Generator

```bash
pip install qrcode[pil]
python3 tools/qr/generate_qr.py "https://example.com/" out.svg
# optional: --logo path/to/logo.svg --color "#3d5394"
```

## Security

- **No secrets** are committed to this repository. All sensitive configuration
  lives in `.env` files which are ignored by `.gitignore`. See `.env.example`
  (where applicable) for the expected variable names.
- GitHub **secret scanning + push protection** are enabled on this repository.
- This repository was initialised from a clean state — it does not share git
  history with our internal site repository.
- If you spot a security issue, please email `bureau@lwpc.lu`. Do not open a
  public issue for security matters.

## Contributing

Pull requests welcome. For substantial changes, please open an issue first to
discuss what you'd like to change.

## License

MIT — see [LICENSE](LICENSE).

## About

Lux-World PC SARL is an IT services company based in Luxembourg, operating
since 1997. Learn more at [lwpc.lu](https://lwpc.lu).
