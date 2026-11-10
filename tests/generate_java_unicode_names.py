"""Regenerate Java 21 script/block names used by the Latin-1 regex oracle."""
import argparse
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("src_zip", type=Path, help="JDK 21 lib/src.zip")
args = parser.parse_args()
with zipfile.ZipFile(args.src_zip) as archive:
    source = archive.read("java.base/java/lang/Character.java").decode("utf-8")
block_source = source[source.index("class UnicodeBlock"):source.index("enum UnicodeScript")]
definitions = re.findall(r"public\s+static\s+final\s+UnicodeBlock\s+(\w+)\s*=\s*new\s+UnicodeBlock\(([^;]+?)\);", block_source, re.S)
blocks = {}
for canonical, arguments in definitions:
    index = 1 if canonical == "BASIC_LATIN" else 2 if canonical == "LATIN_1_SUPPLEMENT" else 0
    for alias in re.findall(r'"([^"]+)"', arguments):
        blocks[alias] = index
with tempfile.TemporaryDirectory() as temp:
    java = Path(temp) / "ScriptList.java"
    java.write_text('import java.util.regex.*; class ScriptList { public static void main(String[] a) { for (var s : Character.UnicodeScript.values()) try { Pattern.compile("\\\\p{Is" + s.name() + "}"); System.out.println(s.name()); } catch (IllegalArgumentException ignored) {} } }', encoding="utf-8")
    subprocess.run(["javac", "-encoding", "UTF-8", str(java)], check=True)
    names = subprocess.run(["java", "-cp", temp, "ScriptList"], check=True, capture_output=True, text=True).stdout.splitlines()
scripts = {name: 1 if name == "LATIN" else 2 if name == "COMMON" else 0 for name in names}
for alias, canonical in re.findall(r'aliases\.put\("([A-Z0-9]+)",\s*(\w+)\)', source):
    if canonical in scripts:
        scripts[alias] = scripts[canonical]
lines = ["// Unicode script and block names from JDK 21 Character.java.", "// Values: 1 = Latin or Basic Latin, 2 = Common or Latin-1 Supplement, 0 = no Latin-1 characters."]
for label, values in [("JAVA_UNICODE_SCRIPT_NAMES", scripts), ("JAVA_UNICODE_BLOCK_NAMES", blocks)]:
    lines.append(f"pub(super) const {label}: &[(&str, u8)] = &[")
    lines.extend(f'    ("{name}", {value}),' for name, value in sorted(values.items()))
    lines.append("];")
(ROOT / "src/java_unicode_names.rs").write_bytes(("\n".join(lines) + "\n").encode())
rows = [f"S:{name}={value}" for name, value in sorted(scripts.items())]
rows += [f"B:{name}={value}" for name, value in sorted(blocks.items())]
(ROOT / "tests/java_unicode_names.txt").write_bytes(("\n".join(rows) + "\n").encode())
