"""Verify the desktop EXE contains the intended Windows icon resource."""
import hashlib
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
expected = hashlib.sha256(Path("resources/g_earth_icon.png").read_bytes()).digest()
if data[:2] != b"MZ":
    raise ValueError("expected a PE executable")
pe = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe:pe + 4] != b"PE\0\0":
    raise ValueError("invalid PE signature")
sections = struct.unpack_from("<H", data, pe + 6)[0]
optional_size = struct.unpack_from("<H", data, pe + 20)[0]
optional = pe + 24
if struct.unpack_from("<H", data, optional)[0] != 0x20B:
    raise ValueError("expected PE32+ executable")
table = optional + optional_size

def file_offset(rva):
    for index in range(sections):
        size, address, raw_size, raw = struct.unpack_from("<IIII", data, table + index * 40 + 8)
        if address <= rva < address + max(size, raw_size):
            result = raw + rva - address
            if result < len(data):
                return result
    raise ValueError("resource RVA outside file sections")

resource_rva, resource_size = struct.unpack_from("<II", data, optional + 112 + 16)
if not resource_rva or not resource_size:
    raise ValueError("missing resource directory")
base = file_offset(resource_rva)

def entries(relative):
    if relative >= resource_size:
        raise ValueError("resource directory outside bounds")
    start = base + relative
    named, numbered = struct.unpack_from("<HH", data, start + 12)
    if named + numbered > 4096:
        raise ValueError("too many resource entries")
    return [struct.unpack_from("<II", data, start + 16 + 8 * i) for i in range(named + numbered)]

def resource(kind, identifier=None):
    items = dict(entries(0))
    entry = items.get(kind)
    if entry is None or not entry & 0x80000000:
        raise ValueError(f"missing resource type {kind}")
    names = entries(entry & 0x7fffffff)
    if identifier is not None:
        names = [item for item in names if item[0] == identifier]
    if not names or not names[0][1] & 0x80000000:
        raise ValueError(f"missing resource item {kind}")
    languages = entries(names[0][1] & 0x7fffffff)
    if not languages or languages[0][1] & 0x80000000:
        raise ValueError(f"missing resource language {kind}")
    relative = languages[0][1]
    if relative + 16 > resource_size:
        raise ValueError("resource data entry outside bounds")
    rva, size = struct.unpack_from("<II", data, base + relative)
    start = file_offset(rva)
    result = data[start:start + size]
    if len(result) != size:
        raise ValueError("truncated resource")
    return result

group = resource(14)
reserved, kind, count = struct.unpack_from("<HHH", group)
if (reserved, kind, count) != (0, 1, 1):
    raise ValueError("unexpected icon group")
width, height, _, _, _, _, image_size, image_id = struct.unpack_from("<BBBBHHIH", group, 6)
icon = resource(3, image_id)
if (width, height) != (64, 64) or len(icon) != image_size or hashlib.sha256(icon).digest() != expected:
    raise ValueError("embedded icon does not match the G-Earth image")
print("Windows executable icon: verified G-Earth 64x64 PNG")
