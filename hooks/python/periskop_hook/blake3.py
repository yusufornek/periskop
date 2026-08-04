"""BLAKE3, written out rather than installed.

data-model.md section 2 fixes one hash for every identity in this project and
names it: blake3, first 8 bytes, 16 lowercase hex. It rejects sha256 by name, so
`hashlib` does not answer the question: CPython ships sha2, blake2b and sha3, and
none of them is blake3. PyPI does, but this package is imported into somebody
else's production interpreter through a `.pth` file, and every distribution it
drags in is one that process is now forced to install and trust. The identity
contract and the zero dependency rule meet here, and this file is the meeting
point.

This is a line for line port of `hooks/node/src/blake3.ts` so that a reader can
diff the two and see that they are the same algorithm. Both are checked against
the same reference vectors (`tests/test_blake3.py`), which is what makes a python
hook and a node hook agree on the identity of one call.

Scope: the 32 byte, unkeyed hash. Keyed hashing and key derivation are not
implemented because no identity in this project uses them.
"""

import struct

_OUT_LEN = 32
_BLOCK_LEN = 64
_CHUNK_LEN = 1024

_CHUNK_START = 1
_CHUNK_END = 2
_PARENT = 4
_ROOT = 8

# Python integers do not wrap, so every arithmetic step masks back to 32 bits.
_MASK32 = 0xFFFFFFFF

_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

_WORDS_FORMAT = struct.Struct("<16I")


def _rotr(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & _MASK32


def _mix(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & _MASK32
    state[d] = _rotr(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotr(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & _MASK32
    state[d] = _rotr(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotr(state[b] ^ state[c], 7)


def _round(state, m):
    _mix(state, 0, 4, 8, 12, m[0], m[1])
    _mix(state, 1, 5, 9, 13, m[2], m[3])
    _mix(state, 2, 6, 10, 14, m[4], m[5])
    _mix(state, 3, 7, 11, 15, m[6], m[7])
    _mix(state, 0, 5, 10, 15, m[8], m[9])
    _mix(state, 1, 6, 11, 12, m[10], m[11])
    _mix(state, 2, 7, 8, 13, m[12], m[13])
    _mix(state, 3, 4, 9, 14, m[14], m[15])


def _compress(chaining, block_words, counter, block_len, flags):
    state = [
        chaining[0], chaining[1], chaining[2], chaining[3],
        chaining[4], chaining[5], chaining[6], chaining[7],
        _IV[0], _IV[1], _IV[2], _IV[3],
        counter & _MASK32,
        (counter >> 32) & _MASK32,
        block_len,
        flags,
    ]
    block = list(block_words)
    for index in range(7):
        _round(state, block)
        if index < 6:
            block = [block[position] for position in _MSG_PERMUTATION]

    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining[i]
    return state


def _block_to_words(block):
    """The 64 byte block as 16 little endian words."""
    return list(_WORDS_FORMAT.unpack(bytes(block)))


class _Output(object):
    """A node of the tree, not yet told whether it is the root."""

    __slots__ = ("chaining", "block_words", "counter", "block_len", "flags")

    def __init__(self, chaining, block_words, counter, block_len, flags):
        self.chaining = chaining
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags


def _chaining_value_of(output):
    return _compress(
        output.chaining, output.block_words, output.counter,
        output.block_len, output.flags,
    )[:8]


def _root_bytes(output):
    # Only the first 64 output bytes are reachable at counter zero, and 32 is
    # all the identity format asks for, so the extended output stream is not
    # built.
    words = _compress(
        output.chaining, output.block_words, 0,
        output.block_len, output.flags | _ROOT,
    )
    return struct.pack("<8I", *words[:8])[:_OUT_LEN]


def _parent_output(left, right, flags):
    return _Output(
        chaining=_IV,
        block_words=list(left) + list(right),
        counter=0,
        block_len=_BLOCK_LEN,
        flags=flags | _PARENT,
    )


class _ChunkState(object):
    __slots__ = ("_chaining", "_block", "_block_len", "_blocks_compressed",
                 "counter", "_flags")

    def __init__(self, chaining, counter, flags):
        self._chaining = list(chaining[:8])
        self._block = bytearray(_BLOCK_LEN)
        self._block_len = 0
        self._blocks_compressed = 0
        self.counter = counter
        self._flags = flags

    def length(self):
        return _BLOCK_LEN * self._blocks_compressed + self._block_len

    def _start_flag(self):
        return _CHUNK_START if self._blocks_compressed == 0 else 0

    def update(self, data):
        offset = 0
        size = len(data)
        while offset < size:
            if self._block_len == _BLOCK_LEN:
                self._chaining = _compress(
                    self._chaining,
                    _block_to_words(self._block),
                    self.counter,
                    _BLOCK_LEN,
                    self._flags | self._start_flag(),
                )[:8]
                self._blocks_compressed += 1
                self._block = bytearray(_BLOCK_LEN)
                self._block_len = 0
            take = min(_BLOCK_LEN - self._block_len, size - offset)
            self._block[self._block_len:self._block_len + take] = (
                data[offset:offset + take])
            self._block_len += take
            offset += take

    def output(self):
        return _Output(
            chaining=self._chaining,
            block_words=_block_to_words(self._block),
            counter=self.counter,
            block_len=self._block_len,
            flags=self._flags | self._start_flag() | _CHUNK_END,
        )


class _Hasher(object):
    __slots__ = ("_chunk", "_stack")

    def __init__(self):
        self._chunk = _ChunkState(_IV, 0, 0)
        self._stack = []

    def update(self, data):
        offset = 0
        size = len(data)
        while offset < size:
            if self._chunk.length() == _CHUNK_LEN:
                chunk_cv = _chaining_value_of(self._chunk.output())
                total_chunks = self._chunk.counter + 1
                self._merge_chunk(chunk_cv, total_chunks)
                self._chunk = _ChunkState(_IV, total_chunks, 0)
            take = min(_CHUNK_LEN - self._chunk.length(), size - offset)
            self._chunk.update(data[offset:offset + take])
            offset += take

    def _merge_chunk(self, chunk_cv, total_chunks):
        """Merge a completed chunk with everything on the stack it completes.

        The number of trailing zero bits of the chunk count says how many merges
        are due, which is what keeps the stack logarithmic in the input length.
        """
        chaining = chunk_cv
        chunks = total_chunks
        while chunks % 2 == 0:
            if not self._stack:
                break
            left = self._stack.pop()
            chaining = _chaining_value_of(_parent_output(left, chaining, 0))
            chunks //= 2
        self._stack.append(chaining)

    def digest(self):
        output = self._chunk.output()
        for index in range(len(self._stack) - 1, -1, -1):
            output = _parent_output(
                self._stack[index], _chaining_value_of(output), 0)
        return _root_bytes(output)


def blake3(data):
    """32 byte unkeyed BLAKE3 digest of the given bytes."""
    hasher = _Hasher()
    hasher.update(data)
    return hasher.digest()


def blake3_short(data):
    """The short form every periskop identity uses: first 8 bytes, lower hex."""
    return blake3(data)[:8].hex()
