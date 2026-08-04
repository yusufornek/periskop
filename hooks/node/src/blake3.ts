// BLAKE3, written out rather than installed.
//
// data-model.md section 2 fixes one hash for every identity in this project and
// names it: blake3, first 8 bytes, 16 lowercase hex. sha256 is rejected there by
// name, so node:crypto does not answer the question. npm does, but a hook is
// loaded into somebody else's production process, and every package it drags in
// is a package that process is now forced to trust. The identity contract and
// the zero-dependency rule meet here, and this file is the meeting point.
//
// Scope: the 32 byte, unkeyed hash. Keyed hashing and key derivation are not
// implemented because no identity in this project uses them.

const OUT_LEN = 32;
const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const MSG_PERMUTATION = new Uint8Array([2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]);

// Every index below is in bounds by construction: the arrays are fixed length
// and the loops are fixed count. The accessor keeps noUncheckedIndexedAccess
// from spraying assertions through the round function, where they would hide
// the shape of the algorithm.
function word(words: Uint32Array, index: number): number {
  return words[index] as number;
}

function byte(bytes: Uint8Array, index: number): number {
  return bytes[index] as number;
}

function rotr(value: number, bits: number): number {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

function mix(
  state: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number,
  mx: number,
  my: number,
): void {
  state[a] = (word(state, a) + word(state, b) + mx) >>> 0;
  state[d] = rotr(word(state, d) ^ word(state, a), 16);
  state[c] = (word(state, c) + word(state, d)) >>> 0;
  state[b] = rotr(word(state, b) ^ word(state, c), 12);
  state[a] = (word(state, a) + word(state, b) + my) >>> 0;
  state[d] = rotr(word(state, d) ^ word(state, a), 8);
  state[c] = (word(state, c) + word(state, d)) >>> 0;
  state[b] = rotr(word(state, b) ^ word(state, c), 7);
}

function round(state: Uint32Array, m: Uint32Array): void {
  mix(state, 0, 4, 8, 12, word(m, 0), word(m, 1));
  mix(state, 1, 5, 9, 13, word(m, 2), word(m, 3));
  mix(state, 2, 6, 10, 14, word(m, 4), word(m, 5));
  mix(state, 3, 7, 11, 15, word(m, 6), word(m, 7));
  mix(state, 0, 5, 10, 15, word(m, 8), word(m, 9));
  mix(state, 1, 6, 11, 12, word(m, 10), word(m, 11));
  mix(state, 2, 7, 8, 13, word(m, 12), word(m, 13));
  mix(state, 3, 4, 9, 14, word(m, 14), word(m, 15));
}

function permute(m: Uint32Array): void {
  const permuted = new Uint32Array(16);
  for (let i = 0; i < 16; i += 1) permuted[i] = word(m, byte(MSG_PERMUTATION, i));
  m.set(permuted);
}

function compress(
  chainingValue: Uint32Array,
  blockWords: Uint32Array,
  counter: number,
  blockLen: number,
  flags: number,
): Uint32Array {
  const state = new Uint32Array(16);
  state.set(chainingValue.subarray(0, 8), 0);
  state.set(IV.subarray(0, 4), 8);
  state[12] = counter >>> 0;
  state[13] = Math.floor(counter / 0x1_0000_0000) >>> 0;
  state[14] = blockLen;
  state[15] = flags;

  const block = Uint32Array.from(blockWords);
  for (let r = 0; r < 7; r += 1) {
    round(state, block);
    if (r < 6) permute(block);
  }

  for (let i = 0; i < 8; i += 1) {
    state[i] = (word(state, i) ^ word(state, i + 8)) >>> 0;
    state[i + 8] = (word(state, i + 8) ^ word(chainingValue, i)) >>> 0;
  }
  return state;
}

function blockToWords(block: Uint8Array, words: Uint32Array): void {
  for (let i = 0; i < 16; i += 1) {
    const at = i * 4;
    words[i] =
      (byte(block, at) |
        (byte(block, at + 1) << 8) |
        (byte(block, at + 2) << 16) |
        (byte(block, at + 3) << 24)) >>>
      0;
  }
}

/** A node of the tree, not yet told whether it is the root. */
interface Output {
  readonly chaining: Uint32Array;
  readonly blockWords: Uint32Array;
  readonly counter: number;
  readonly blockLen: number;
  readonly flags: number;
}

function chainingValueOf(output: Output): Uint32Array {
  return compress(
    output.chaining,
    output.blockWords,
    output.counter,
    output.blockLen,
    output.flags,
  ).slice(0, 8);
}

function rootBytes(output: Output): Uint8Array {
  // Only the first 64 output bytes are reachable at counter zero, and 32 is all
  // the identity format asks for, so the extended output stream is not built.
  const words = compress(output.chaining, output.blockWords, 0, output.blockLen, output.flags | ROOT);
  const bytes = new Uint8Array(OUT_LEN);
  for (let i = 0; i < 8; i += 1) {
    const value = word(words, i);
    bytes[i * 4] = value & 0xff;
    bytes[i * 4 + 1] = (value >>> 8) & 0xff;
    bytes[i * 4 + 2] = (value >>> 16) & 0xff;
    bytes[i * 4 + 3] = (value >>> 24) & 0xff;
  }
  return bytes;
}

function parentOutput(left: Uint32Array, right: Uint32Array, flags: number): Output {
  const blockWords = new Uint32Array(16);
  blockWords.set(left, 0);
  blockWords.set(right, 8);
  return { chaining: IV, blockWords, counter: 0, blockLen: BLOCK_LEN, flags: flags | PARENT };
}

class ChunkState {
  #chaining: Uint32Array;
  readonly #block = new Uint8Array(BLOCK_LEN);
  readonly #words = new Uint32Array(16);
  #blockLen = 0;
  #blocksCompressed = 0;

  constructor(
    chaining: Uint32Array,
    readonly counter: number,
    private readonly flags: number,
  ) {
    this.#chaining = chaining.slice(0, 8);
  }

  length(): number {
    return BLOCK_LEN * this.#blocksCompressed + this.#blockLen;
  }

  #startFlag(): number {
    return this.#blocksCompressed === 0 ? CHUNK_START : 0;
  }

  update(input: Uint8Array): void {
    let offset = 0;
    while (offset < input.length) {
      if (this.#blockLen === BLOCK_LEN) {
        blockToWords(this.#block, this.#words);
        this.#chaining = compress(
          this.#chaining,
          this.#words,
          this.counter,
          BLOCK_LEN,
          this.flags | this.#startFlag(),
        ).slice(0, 8);
        this.#blocksCompressed += 1;
        this.#block.fill(0);
        this.#blockLen = 0;
      }
      const take = Math.min(BLOCK_LEN - this.#blockLen, input.length - offset);
      this.#block.set(input.subarray(offset, offset + take), this.#blockLen);
      this.#blockLen += take;
      offset += take;
    }
  }

  output(): Output {
    const blockWords = new Uint32Array(16);
    blockToWords(this.#block, blockWords);
    return {
      chaining: this.#chaining,
      blockWords,
      counter: this.counter,
      blockLen: this.#blockLen,
      flags: this.flags | this.#startFlag() | CHUNK_END,
    };
  }
}

class Hasher {
  #chunk = new ChunkState(IV, 0, 0);
  readonly #stack: Uint32Array[] = [];

  update(input: Uint8Array): void {
    let offset = 0;
    while (offset < input.length) {
      if (this.#chunk.length() === CHUNK_LEN) {
        const chunkCv = chainingValueOf(this.#chunk.output());
        const totalChunks = this.#chunk.counter + 1;
        this.#mergeChunk(chunkCv, totalChunks);
        this.#chunk = new ChunkState(IV, totalChunks, 0);
      }
      const take = Math.min(CHUNK_LEN - this.#chunk.length(), input.length - offset);
      this.#chunk.update(input.subarray(offset, offset + take));
      offset += take;
    }
  }

  // A completed chunk merges with everything on the stack that it completes.
  // The number of trailing zero bits of the chunk count says how many merges
  // are due, which is what keeps the stack logarithmic in the input length.
  #mergeChunk(chunkCv: Uint32Array, totalChunks: number): void {
    let cv = chunkCv;
    let chunks = totalChunks;
    while (chunks % 2 === 0) {
      const left = this.#stack.pop();
      if (left === undefined) break;
      cv = chainingValueOf(parentOutput(left, cv, 0));
      chunks = Math.floor(chunks / 2);
    }
    this.#stack.push(cv);
  }

  digest(): Uint8Array {
    let output = this.#chunk.output();
    for (let i = this.#stack.length - 1; i >= 0; i -= 1) {
      output = parentOutput(this.#stack[i] as Uint32Array, chainingValueOf(output), 0);
    }
    return rootBytes(output);
  }
}

/** 32 byte unkeyed BLAKE3 digest of the given bytes. */
export function blake3(input: Uint8Array): Uint8Array {
  const hasher = new Hasher();
  hasher.update(input);
  return hasher.digest();
}

/** The short form every periskop identity uses: first 8 bytes, lowercase hex. */
export function blake3Short(input: Uint8Array): string {
  const digest = blake3(input);
  let hex = "";
  for (let i = 0; i < 8; i += 1) hex += byte(digest, i).toString(16).padStart(2, "0");
  return hex;
}
