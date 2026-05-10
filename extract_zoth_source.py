"""Extract Zoth's verified contract source files from the Etherscan V2 API response.

Etherscan returns multi-file contracts with a quirky double-brace JSON wrapper.
This script strips the wrapper, parses the inner JSON, and writes each source
file to disk preserving the original directory structure.

Output goes to src/zoth/ relative to project root.
"""

import json
import os
from pathlib import Path

# Load the Etherscan response
with open("zoth_source.json") as f:
    response = json.load(f)

raw_source = response["result"][0]["SourceCode"]

# Strip Etherscan's double-brace wrapper. The inner content is itself JSON.
if raw_source.startswith("{{") and raw_source.endswith("}}"):
    inner_json = raw_source[1:-1]
else:
    raise ValueError("Unexpected SourceCode format")

source_data = json.loads(inner_json)

# source_data["sources"] is a dict mapping file paths -> {"content": "..."}
sources = source_data["sources"]

print(f"Found {len(sources)} source files")
print(f"Compiler settings:")
settings = source_data.get("settings", {})
print(f"  Optimizer: {settings.get('optimizer', {})}")
print(f"  EVM version: {settings.get('evmVersion', 'default')}")
print()

# Write each source file to src/zoth/, preserving relative paths.
output_root = Path("src/zoth")
output_root.mkdir(parents=True, exist_ok=True)

for relative_path, file_obj in sources.items():
    output_path = output_root / relative_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(file_obj["content"])
    print(f"  wrote {output_path} ({len(file_obj['content'])} chars)")

print()
print("Done. Source extracted to src/zoth/")