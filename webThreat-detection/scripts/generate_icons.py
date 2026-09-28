"""
Generate PNG icons for the Phishing Detection Chrome Extension.
Uses pure Python standard library (struct and zlib) to create valid RGBA PNG images.
"""

import os
import struct
import zlib


def create_png(width: int, height: int, rgba_func, filepath: str) -> None:
    """Generate a valid RGBA PNG image with the given pixel generator function."""
    raw_bytes = bytearray()
    for y in range(height):
        raw_bytes.append(0)  # Filter byte: None
        for x in range(width):
            r, g, b, a = rgba_func(x, y, width, height)
            raw_bytes.extend((r, g, b, a))

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return length + chunk_type + data + crc

    header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)
    idat = make_chunk(b"IDAT", zlib.compress(bytes(raw_bytes), level=9))
    iend = make_chunk(b"IEND", b"")

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(header + ihdr + idat + iend)
    print(f"Generated icon: {filepath}")


def icon_shield(x, y, w, h):
    """Draw a blue security shield."""
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.44
    dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    if dist <= r:
        # Gradient shield in blue/indigo
        factor = y / h
        red = int(37 + factor * 20)
        green = int(99 + factor * 40)
        blue = int(235 - factor * 30)
        return (red, green, blue, 255)
    return (0, 0, 0, 0)


def icon_safe(x, y, w, h):
    """Draw a bright green verified checkmark / safe circle badge."""
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.44
    dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    if dist <= r:
        return (22, 163, 74, 255)  # Emerald green #16A34A
    return (0, 0, 0, 0)


def icon_danger(x, y, w, h):
    """Draw a bold red warning / fraud alert badge."""
    cx, cy = w / 2, h / 2
    r = min(w, h) * 0.44
    dist = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    if dist <= r:
        return (220, 38, 38, 255)  # Bright Red #DC2626
    return (0, 0, 0, 0)


def main():
    icons_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "extension", "icons")
    )
    os.makedirs(icons_dir, exist_ok=True)

    print(f"Generating extension icons in: {icons_dir}")

    create_png(16, 16, icon_shield, os.path.join(icons_dir, "icon16.png"))
    create_png(48, 48, icon_shield, os.path.join(icons_dir, "icon48.png"))
    create_png(128, 128, icon_shield, os.path.join(icons_dir, "icon128.png"))
    create_png(128, 128, icon_safe, os.path.join(icons_dir, "icon_safe.png"))
    create_png(128, 128, icon_danger, os.path.join(icons_dir, "icon_danger.png"))

    print("All icons successfully generated!")


if __name__ == "__main__":
    main()
