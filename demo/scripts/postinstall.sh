#!/bin/sh
# Patch @ethereumjs/trie to remove missing isHexPrefixed import
# (removed from @ethereumjs/util in newer versions that tevm co-installs)
FILE="node_modules/@tevm/trie/node_modules/@ethereumjs/trie/dist/esm/util/genesisState.js"
if [ -f "$FILE" ] && grep -q "isHexPrefixed" "$FILE" 2>/dev/null; then
  sed -i.bak \
    's/import { Account, isHexPrefixed, toBytes, unpadBytes, unprefixedHexToBytes } from .@ethereumjs\/util./import { Account, toBytes, unpadBytes, unprefixedHexToBytes } from "@ethereumjs\/util";\nfunction isHexPrefixed(str) { return typeof str === "string" \&\& str.startsWith("0x"); }/' \
    "$FILE"
  rm -f "${FILE}.bak"
  echo "Patched @ethereumjs/trie isHexPrefixed import"
fi
