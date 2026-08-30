#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$script_dir"

for command in clang node wasm-pack; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'error: required command not found: %s\n' "$command" >&2
    exit 1
  }
done

export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-clang}"

cargo test --locked --package mercury-web-wallet --lib
wasm-pack build --target web --release --locked
rm -f pkg/.gitignore
node --input-type=module -e 'import fs from "node:fs"; const path = "pkg/package.json"; const pkg = JSON.parse(fs.readFileSync(path, "utf8")); pkg.private = true; fs.writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`); const written = JSON.parse(fs.readFileSync(path, "utf8")); if (written.private !== true) throw new Error("generated package must be private");'
