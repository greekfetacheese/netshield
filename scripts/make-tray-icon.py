#!/usr/bin/env python3
"""Generate the NetShield tray icon: a green shield with a dark check mark.

The GUI embeds the icon as a raw byte slice, so this script writes two files:

  crates/netshield-gui/assets/tray-icon.rgba
      Raw, row-major, top-down RGBA8 pixels, exactly ``64 * 64 * 4`` bytes (16384),
      with no header and no compression.  This is the file Rust includes: the GUI
      needs no PNG decoder at build time or at run time, and ``tray_icon::Icon::
      from_rgba`` takes exactly this layout.

  crates/netshield-gui/assets/tray-icon.png
      A 64x64 preview for humans (READMEs, icons in file managers).  Not embedded.

Both are deterministic for a given Pillow version.  ``--check`` regenerates them in
memory and compares against the committed files, exiting non-zero on any difference
so a stale icon fails a check instead of silently shipping.

The drawing is supersampled 4x and downsampled with a premultiplied-alpha resize, so
the antialiased edge does not pick up a dark fringe from the transparent background.

Usage:
    python3 scripts/make-tray-icon.py           # write both files
    python3 scripts/make-tray-icon.py --check   # verify the committed files
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PIL import Image, ImageDraw

SIDE = 64
SUPERSAMPLE = 4
SCALE = SIDE * SUPERSAMPLE

# The ALLOWED green used elsewhere in the GUI, and a near-black green for the check.
GREEN = (0x6C, 0xC0, 0x7A)
DARK = (0x14, 0x2A, 0x1A)
CHECK_WIDTH = 4.2

ASSETS = Path(__file__).resolve().parent.parent / "crates/netshield-gui/assets"
PNG_PATH = ASSETS / "tray-icon.png"
RGBA_PATH = ASSETS / "tray-icon.rgba"


def _quad(p0, p1, p2, steps):
    """Sample a quadratic Bezier from p0 to p2 with control p1."""
    return [
        (
            (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t**2 * p2[0],
            (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t**2 * p2[1],
        )
        for t in (i / steps for i in range(1, steps + 1))
    ]


def _cubic(p0, p1, p2, p3, steps):
    """Sample a cubic Bezier from p0 to p3 with controls p1 and p2."""
    return [
        (
            (1 - t) ** 3 * p0[0]
            + 3 * (1 - t) ** 2 * t * p1[0]
            + 3 * (1 - t) * t**2 * p2[0]
            + t**3 * p3[0],
            (1 - t) ** 3 * p0[1]
            + 3 * (1 - t) ** 2 * t * p1[1]
            + 3 * (1 - t) * t**2 * p2[1]
            + t**3 * p3[1],
        )
        for t in (i / steps for i in range(1, steps + 1))
    ]


def _shield() -> list[tuple[float, float]]:
    """The shield outline in 64x64 space: rounded top, curved sides, bottom point."""
    points = [(8.0, 14.0)]
    points += _quad((8.0, 14.0), (8.0, 5.0), (16.0, 5.0), 12)  # top-left corner
    points += _quad((16.0, 5.0), (48.0, 5.0), (48.0, 5.0), 1)  # top edge
    points += _quad((48.0, 5.0), (56.0, 5.0), (56.0, 14.0), 12)  # top-right corner
    points += _cubic((56.0, 14.0), (56.0, 34.0), (48.0, 50.0), (32.0, 60.0), 40)
    points += _cubic((32.0, 60.0), (16.0, 50.0), (8.0, 34.0), (8.0, 14.0), 40)
    return points


def _signed_area(points) -> float:
    area = 0.0
    for (x0, y0), (x1, y1) in zip(points, points[1:] + points[:1]):
        area += x0 * y1 - x1 * y0
    return area / 2.0


def _inset(points, distance: float) -> list[tuple[float, float]]:
    """Offset a closed polygon inward by ``distance`` along each vertex normal."""
    inward = 1.0 if _signed_area(points) > 0 else -1.0
    result = []
    count = len(points)
    for index, (x, y) in enumerate(points):
        prev_x, prev_y = points[index - 1]
        next_x, next_y = points[(index + 1) % count]
        tangent_x, tangent_y = next_x - prev_x, next_y - prev_y
        length = (tangent_x**2 + tangent_y**2) ** 0.5 or 1.0
        # The inward normal of a positively wound polygon is (-ty, tx) rotated the
        # other way once the sign is folded in.
        nx, ny = inward * -tangent_y / length, inward * tangent_x / length
        result.append((x + nx * distance, y + ny * distance))
    return result


def _scaled(points):
    return [(x * SUPERSAMPLE, y * SUPERSAMPLE) for x, y in points]


def render() -> Image.Image:
    """Draw the 64x64 RGBA icon."""
    outer = _scaled(_shield())
    inner = _scaled(_inset(_shield(), 3.0))

    # Fully opaque green outline on a transparent background, then the interior
    # repainted as a soft green fill: the stroke keeps its full opacity.
    image = Image.new("RGBA", (SCALE, SCALE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon(outer, fill=GREEN + (255,))
    draw.polygon(inner, fill=GREEN + (90,))

    # The check mark, drawn as two thick round-capped strokes in the dark accent colour.
    stroke = CHECK_WIDTH * SUPERSAMPLE
    first = ((23.0, 32.5), (29.5, 39.0))
    second = ((29.5, 39.0), (41.5, 25.5))
    for (x0, y0), (x1, y1) in (first, second):
        draw.line(
            (x0 * SUPERSAMPLE, y0 * SUPERSAMPLE, x1 * SUPERSAMPLE, y1 * SUPERSAMPLE),
            fill=DARK + (255,),
            width=round(stroke),
        )
    for x, y in (first[0], first[1], second[1]):
        radius = stroke / 2.0
        draw.ellipse(
            (
                x * SUPERSAMPLE - radius,
                y * SUPERSAMPLE - radius,
                x * SUPERSAMPLE + radius,
                y * SUPERSAMPLE + radius,
            ),
            fill=DARK + (255,),
        )

    # Premultiplied resize: resizing straight RGBA would blend towards the black of the
    # transparent pixels and leave a dark halo around the shield.
    return (
        image.convert("RGBa")
        .resize((SIDE, SIDE), Image.Resampling.LANCZOS)
        .convert("RGBA")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in memory and fail if the committed files are stale",
    )
    args = parser.parse_args()

    icon = render()
    raw = icon.tobytes()
    if len(raw) != SIDE * SIDE * 4:
        raise SystemExit(f"generated {len(raw)} bytes, expected {SIDE * SIDE * 4}")

    if args.check:
        ok = True
        if not RGBA_PATH.exists():
            print(f"missing {RGBA_PATH}", file=sys.stderr)
            ok = False
        elif RGBA_PATH.read_bytes() != raw:
            print(f"{RGBA_PATH} is stale; run python3 scripts/make-tray-icon.py", file=sys.stderr)
            ok = False
        if not PNG_PATH.exists():
            print(f"missing {PNG_PATH}", file=sys.stderr)
            ok = False
        else:
            committed = Image.open(PNG_PATH).convert("RGBA")
            if committed.size != (SIDE, SIDE) or committed.tobytes() != raw:
                print(
                    f"{PNG_PATH} is stale; run python3 scripts/make-tray-icon.py",
                    file=sys.stderr,
                )
                ok = False
        if not ok:
            return 1
        print(f"{RGBA_PATH.name} and {PNG_PATH.name} are up to date")
        return 0

    ASSETS.mkdir(parents=True, exist_ok=True)
    icon.save(PNG_PATH)
    RGBA_PATH.write_bytes(raw)
    print(f"wrote {PNG_PATH} ({PNG_PATH.stat().st_size} bytes)")
    print(f"wrote {RGBA_PATH} ({len(raw)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
