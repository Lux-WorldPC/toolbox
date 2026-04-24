# toolbox

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Live demo](https://img.shields.io/badge/live_demo-lwpc.lu%2Ftoolbox-3d5394)](https://lwpc.lu/lb/toolbox/)
[![Tools](https://img.shields.io/badge/tools-2%2F6_published-brightgreen)](#available-tools)

Open-source IT utilities from [lwpc.lu](https://lwpc.lu).

This repository contains the source code of the utilities available at
[lwpc.lu/toolbox/](https://lwpc.lu/lb/toolbox/). Everything runs client-side
unless otherwise specified. No data leaves the browser for tools marked
**100% local**.

Published under the MIT License so anyone can audit, reuse, adapt, or self-host.

**▶ [Try the live demo on lwpc.lu/toolbox/](https://lwpc.lu/lb/toolbox/)**

## Available tools

| Tool | Status | Live demo |
|---|---|---|
| Password Generator (Classic + Passphrase) | ✅ published | [/toolbox/password/](https://lwpc.lu/lb/toolbox/password/) |
| QR Code Generator (CLI, Python) | ✅ published | — |
| Secure Message | ⏳ planned | [/toolbox/secret/](https://lwpc.lu/lb/toolbox/secret/) |
| Domain Checkup | ⏳ planned | [/toolbox/domain/](https://lwpc.lu/lb/toolbox/domain/) |
| What's My IP | ⏳ planned | [/toolbox/myip/](https://lwpc.lu/lb/toolbox/myip/) |
| Email Header Analyzer | ⏳ planned | [/toolbox/email-headers/](https://lwpc.lu/lb/toolbox/email-headers/) |

More tools will be published progressively after each is reviewed for safety
(no secrets, no internal paths, no site-specific logic).

## Layout

```
frontend/         Client-side tools (HTML + JS + CSS, no build step)
  password/         Password Generator — runs fully offline
backend/          Server-side components (published after review)
tools/            Standalone utilities
  qr/               Python QR code generator (CLI)
```

## Run locally

### Password Generator

```bash
git clone https://github.com/Lux-WorldPC/toolbox.git
cd toolbox/frontend/password
python3 -m http.server 8000
# open http://localhost:8000/
```

100% offline — no network calls, no trackers, no backend. Works from `file://`
as well.

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
