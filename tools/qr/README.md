# QR Code Generator

Clean SVG QR code generator with an optional centered logo. Pure SVG output,
no bitmap, no embedded JavaScript, no external dependency at render time.

## Install

```bash
pip install 'qrcode[pil]'
# Optional: for SVG logos
# Debian/Ubuntu:  sudo apt install librsvg2-bin
# macOS (Homebrew): brew install librsvg
```

## Usage

```bash
# Print SVG to stdout
python3 generate_qr.py "https://example.com/"

# Write to file
python3 generate_qr.py "https://example.com/" qr.svg

# Custom color
python3 generate_qr.py "https://example.com/" qr.svg --color "#3d5394"

# With a centered logo
python3 generate_qr.py "https://example.com/" qr.svg --logo logo.svg
python3 generate_qr.py "https://example.com/" qr.svg --logo logo.png
```

## Notes

- QR version 3 (29x29 modules), error correction level M (15%). Leaves room
  for a ~25% centered logo without breaking readability.
- Data modules are rendered at 2/3 of cell size for a cleaner, slightly
  spaced look compared to solid QR codes.
- Finder patterns are drawn as proper rings (outer 7x7 minus inner 5x5, using
  `fill-rule: evenodd`) rather than as filled blocks — matches the rendering
  of major QR styling tools.
- SVG logos are rasterized to PNG at 258x258 px (via `rsvg-convert`) before
  being embedded as base64 — keeps the output a single self-contained file.
