packageName   = "eth_keys"
version       = "0.0.2"
author        = "Status Research & Development GmbH"
description   = "A reimplementation in pure Nim of eth-keys, the common API for Ethereum key operations."
license       = "Apache License 2.0 or MIT"
# srcDir        = "src"
skipDirs      = @["src", "tests", "Nim", "old_api"]

### Dependencies

requires "nim > 0.18.0",
         "nimcrypto",
         "secp256k1"

proc test(name: string, lang: string = "c") =
  if not dirExists "build":
    mkDir "build"
  if not dirExists "nimcache":
    mkDir "nimcache"
  --run
  --nimcache: "nimcache"
  switch("out", ("./build/" & name))
  setCommand lang, "tests/" & name & ".nim"

task test, "Run all tests - C only & libsecp256k1 backend":
  test "tests"

# task test_cpp, "Run all tests - C++ only & libsecp256k1 backend":
#   test "all_tests", "cpp"

# task test, "Run all tests - C and C++ & libsecp256k1 backend":
#   exec "nimble test_c"
#   exec "rm ./nimcache/*"
#   exec "nimble test_cpp"

# task test_backend_native, "Run all tests - pure Nim backend":
#   switch("define", "backend_native")
#   test "all_tests", "cpp"
