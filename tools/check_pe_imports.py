"""Check the development EXE imports without executing it (stdlib only)."""
import struct
import sys
from pathlib import Path

data = Path(sys.argv[1]).read_bytes()
if len(data) > 64 * 1024 * 1024 or data[:2] != b"MZ":
    raise ValueError("expected a bounded PE executable")
pe = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe:pe + 4] != b"PE\0\0":
    raise ValueError("invalid PE signature")
machine, sections = struct.unpack_from("<HH", data, pe + 4)
optional_size = struct.unpack_from("<H", data, pe + 20)[0]
optional = pe + 24
if machine != 0x8664 or struct.unpack_from("<H", data, optional)[0] != 0x20B:
    raise ValueError("expected Windows x64 PE32+")
table = optional + optional_size

def offset(rva):
    for index in range(sections):
        size, address, raw_size, raw = struct.unpack_from("<IIII", data, table + 40 * index + 8)
        if address <= rva < address + max(size, raw_size):
            result = raw + rva - address
            if result >= len(data):
                break
            return result
    raise ValueError("import RVA outside file sections")

imports = []
import_rva, import_size = struct.unpack_from("<II", data, optional + 112 + 8)
if import_rva:
    start = offset(import_rva)
    for index in range(min(import_size // 20 + 1, 4096)):
        descriptor = struct.unpack_from("<IIIII", data, start + 20 * index)
        if not any(descriptor):
            break
        name = offset(descriptor[3])
        end = data.index(0, name, min(name + 256, len(data)))
        imports.append(data[name:end].decode("ascii"))
    else:
        raise ValueError("unterminated import descriptors")
print("Windows x64 DLL imports:", ", ".join(sorted(imports)))
if any(name.lower().startswith(("vcruntime", "msvcp", "msvcr")) for name in imports):
    raise ValueError("development EXE unexpectedly requires an external Visual C++ runtime")
