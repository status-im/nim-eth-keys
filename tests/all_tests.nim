# Copyright (c) 2018 Status Research & Development GmbH
# Distributed under the MIT License (license terms are at http://opensource.org/licenses/MIT).


when defined(backend_native):
  echo "\nBackend tested: native\n"
else:
  echo "\nBackend tested: libsecp256k1\n"

import  ./test_hex_bytes_conversion,
        ./test_private_public_key_consistency,
        ./test_key_and_signature_datastructures
