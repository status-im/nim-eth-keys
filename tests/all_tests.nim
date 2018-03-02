# Nim Eth-keys
# Copyright 2018 Status Research & Development GmbH
# Licensed under either of
#
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
#
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when defined(backend_native):
  echo "\nBackend tested: native\n"
else:
  echo "\nBackend tested: libsecp256k1\n"

import  ./test_hex_bytes_conversion,
        ./test_private_public_key_consistency,
        ./test_key_and_signature_datastructures
