#!/usr/bin/env python3
"""
generate_qr.py — Generate a clean SVG QR code with an optional centered logo.

Features
  · Pure SVG output (no bitmap, no embedded JS, no external dependency at render)
  · Rounded data modules (2/3 of cell size) for a modern look
  · Customizable fill color
  · Optional centered logo (SVG rasterized to PNG via rsvg-convert, or PNG direct)
  · QR version 3 (29x29), ERROR_CORRECT_M (15% correction — leaves room for logo)

Usage
  python3 generate_qr.py URL [OUTPUT.svg]
  python3 generate_qr.py URL out.svg --color "#3d5394" --logo logo.svg

Dependencies
  pip install qrcode[pil]
  (optional) rsvg-convert   for SVG logos   e.g. apt install librsvg2-bin

Examples
  generate_qr.py "https://example.com/"                   # prints SVG to stdout
  generate_qr.py "https://example.com/" qr.svg
  generate_qr.py "https://example.com/" qr.svg --color "#000000"
  generate_qr.py "https://example.com/" qr.svg --logo brand.svg

Published as part of the @lwpc/toolbox repository — MIT License.
"""

import argparse
import base64
import os
import subprocess
import sys
import tempfile

try:
    import qrcode
except ImportError:
    print("Missing dependency: pip install 'qrcode[pil]'", file=sys.stderr)
    sys.exit(1)


# ── Render parameters ────────────────────────────────────────────────────────
VIEWBOX    = 500
PADDING    = 20
GRID       = 29                              # QR version 3 (29x29 modules)
CELL       = (VIEWBOX - 2 * PADDING) / GRID  # ~15.862
MODULE     = CELL * 2 / 3                    # ~10.575 (rounded data modules)
LOGO_XY    = 185.6                           # centered: 185.6 + 128.8/2 = 250
LOGO_SIZE  = 128.8
LOGO_PNG_PX = 258                            # logo rasterization resolution

# Finder pattern zones — these cells are drawn by outer/inner eye functions,
# not as regular data modules
FINDER_ZONES = (
    frozenset((r, c) for r in range(7) for c in range(7))              # top-left
    | frozenset((r, c) for r in range(7) for c in range(22, 29))       # top-right
    | frozenset((r, c) for r in range(22, 29) for c in range(7))       # bottom-left
)


def module_path(row: int, col: int) -> str:
    """SVG path for one data module (rectangle)."""
    x = PADDING + col * CELL
    y = PADDING + row * CELL
    m = MODULE
    return f"M{x:.6f},{y:.6f}H{x+m:.6f}V{y+m:.6f}H{x:.6f}Z"


def outer_eye(tx: float, ty: float) -> str:
    """Outer ring of a finder pattern (7x7 minus 5x5 inner, via evenodd)."""
    s1 = CELL
    s6 = 6 * CELL
    s7 = 7 * CELL
    outer = f"M{tx:.6f},{ty:.6f}H{tx+s7:.6f}V{ty+s7:.6f}H{tx:.6f}Z"
    inner = f"M{tx+s1:.6f},{ty+s1:.6f}H{tx+s6:.6f}V{ty+s6:.6f}H{tx+s1:.6f}Z"
    return outer + " " + inner


def inner_eye(tx: float, ty: float) -> str:
    """Center square of a finder pattern (3x3 at offset 2)."""
    s2 = 2 * CELL
    s5 = 5 * CELL
    return f"M{tx+s2:.6f},{ty+s2:.6f}H{tx+s5:.6f}V{ty+s5:.6f}H{tx+s2:.6f}Z"


def qr_matrix(url: str):
    """Returns the boolean module matrix from qrcode lib."""
    qr = qrcode.QRCode(
        version=3,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=0,
    )
    qr.add_data(url, optimize=0)
    qr.make(fit=False)
    return qr.modules


def load_logo_b64(logo_path: str) -> str:
    """Load a logo file and return it as base64-encoded PNG.
    Supports .svg (requires rsvg-convert) and .png directly."""
    ext = os.path.splitext(logo_path)[1].lower()

    if ext == ".png":
        with open(logo_path, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")

    if ext == ".svg":
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            subprocess.run(
                ["rsvg-convert", "-w", str(LOGO_PNG_PX), "-h", str(LOGO_PNG_PX),
                 "-b", "white", logo_path, "-o", tmp_path],
                check=True, capture_output=True,
            )
            with open(tmp_path, "rb") as f:
                return base64.b64encode(f.read()).decode("ascii")
        except FileNotFoundError:
            print("rsvg-convert not found — install librsvg2-bin or pass a PNG logo",
                  file=sys.stderr)
            sys.exit(1)
        finally:
            os.unlink(tmp_path)

    print(f"Unsupported logo format: {ext} (use .svg or .png)", file=sys.stderr)
    sys.exit(1)


def generate_svg(url: str, color: str, logo_b64: str | None) -> str:
    matrix = qr_matrix(url)
    assert len(matrix) == GRID, f"Expected {GRID}x{GRID}, got {len(matrix)}x{len(matrix[0])}"

    data_paths = []
    for row, row_data in enumerate(matrix):
        for col, dark in enumerate(row_data):
            if dark and (row, col) not in FINDER_ZONES:
                data_paths.append(
                    f'<path d="{module_path(row, col)}" fill="{color}"/>'
                )

    tl_x, tl_y = PADDING, PADDING
    tr_x, tr_y = PADDING + 22 * CELL, PADDING
    bl_x, bl_y = PADDING, PADDING + 22 * CELL

    finder_els = []
    for fx, fy in [(tl_x, tl_y), (tr_x, tr_y), (bl_x, bl_y)]:
        finder_els.append(
            f'<path d="{outer_eye(fx, fy)}" fill="{color}" fill-rule="evenodd"/>'
        )
    for fx, fy in [(tl_x, tl_y), (tr_x, tr_y), (bl_x, bl_y)]:
        finder_els.append(f'<path d="{inner_eye(fx, fy)}" fill="{color}"/>')

    modules_svg = "\n  ".join(data_paths)
    finders_svg = "\n  ".join(finder_els)

    logo_svg = ""
    if logo_b64:
        logo_svg = (
            f'\n  <image x="{LOGO_XY}" y="{LOGO_XY}" '
            f'width="{LOGO_SIZE}" height="{LOGO_SIZE}" '
            f'xlink:href="data:image/png;base64,{logo_b64}"/>'
        )

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"\n'
        f'     width="512" height="512" viewBox="0 0 {VIEWBOX} {VIEWBOX}" xml:space="preserve">\n'
        f'  <rect width="{VIEWBOX}" height="{VIEWBOX}" x="0" y="0" fill="#ffffff"/>\n'
        f'  {modules_svg}\n'
        f'  {finders_svg}'
        f'{logo_svg}\n'
        '</svg>\n'
    )


def main():
    ap = argparse.ArgumentParser(description="Generate a clean SVG QR code.")
    ap.add_argument("url", help="The URL or text to encode")
    ap.add_argument("output", nargs="?", default="-",
                    help="Output .svg file (default: stdout)")
    ap.add_argument("--color", default="#000000",
                    help="Module color (default: #000000)")
    ap.add_argument("--logo", default=None,
                    help="Optional logo file to embed in the center (.svg or .png)")
    args = ap.parse_args()

    logo_b64 = load_logo_b64(args.logo) if args.logo else None
    svg = generate_svg(args.url, args.color, logo_b64)

    if args.output == "-":
        sys.stdout.write(svg)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(svg)
        print(f"[ok] {args.output} ({os.path.getsize(args.output) / 1024:.1f} KB)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
