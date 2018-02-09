packageName   = "eth_keys"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "A reimplementation in pure Nim of eth-keys, the common API for Ethereum key operations."
license       = "MIT"
srcDir        = "src"

### Dependencies
requires "nim >= 0.17.2", "keccak_tiny >= 0.1.0", "ttmath >= 0.1.0"

proc test(name: string, lang: string = "c") =
  if not dirExists "build":
    mkDir "build"
  if not dirExists "nimcache":
    mkDir "nimcache"
  --run
  --nimcache: "nimcache"
  switch("out", ("./build/" & name))
  setCommand lang, "tests/" & name & ".nim"