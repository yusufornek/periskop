"""The hand written hash, held to the reference vectors.

A hash implemented in this repository rather than installed is only worth having
if it is the same function everyone else computes. These vectors are the ones
`hooks/node/src/blake3.test.ts` uses, byte for byte, so a failure here is also
the failure that would make a python hook and a node hook disagree on the
identity of one call.

The input for a length N is the repeating byte pattern `i % 251`, which is the
pattern the official BLAKE3 test set uses. The lengths cross every boundary the
implementation has: single block, block edge, chunk edge, and several levels of
the parent tree.
"""

import unittest

from periskop_hook.blake3 import blake3, blake3_short

VECTORS = (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
    (2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"),
    (3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"),
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
    (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
    (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
    (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"),
    (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
)

# The separator the identity formula joins fields with.
UNIT_SEPARATOR = "\x1f"

STRING_VECTORS = (
    ("abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    ("periskop",
     "ccbfc5c0d76f82d6c780f0f364c4eaa4cec7adc876e4f2badb1c58a59b9c1402"),
    (UNIT_SEPARATOR.join(["ee/v1", "node/26", "api.openai.com:443"]),
     "ed11bc99653a5e2e875ab9d9e98919ec169a08740f0bbaf085cc6462b41ae792"),
)


def _pattern(length):
    return bytes(index % 251 for index in range(length))


class ReferenceVectorTest(unittest.TestCase):
    def test_digest_matches_the_reference_at_every_boundary(self):
        for length, expected in VECTORS:
            self.assertEqual(
                expected, blake3(_pattern(length)).hex(),
                "length {0}".format(length))

    def test_digest_matches_for_the_strings_identities_are_built_from(self):
        for text, expected in STRING_VECTORS:
            self.assertEqual(
                expected, blake3(text.encode("utf-8")).hex(), repr(text))

    def test_the_short_form_is_eight_bytes_as_sixteen_lowercase_hex(self):
        short = blake3_short(b"periskop")
        self.assertRegex(short, r"^[0-9a-f]{16}$")
        self.assertEqual("ccbfc5c0d76f82d6", short)

    def test_the_digest_is_the_full_thirty_two_bytes(self):
        self.assertEqual(32, len(blake3(b"")))

    def test_a_bytearray_hashes_the_same_as_the_bytes_it_holds(self):
        # The recorder assembles the identity input in a bytearray, so the two
        # spellings have to agree or the identity would depend on plumbing.
        self.assertEqual(blake3(b"periskop"), blake3(bytearray(b"periskop")))


if __name__ == "__main__":
    unittest.main()
