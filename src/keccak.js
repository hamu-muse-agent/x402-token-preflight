// Minimal Keccak-256 (original Keccak padding 0x01, NOT SHA3-256) implemented
// with BigInt lanes. Used only to derive 4-byte function selectors from
// signature strings, so the selector table in check.js stays human-auditable
// and cannot silently contain a wrong constant.
//
// Self-test vectors (asserted in test/verify-check.mjs):
//   keccak256("")                          = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
//   selector("transfer(address,uint256)")  = a9059cbb
//   selector("owner()")                    = 8da5cb5b

const MASK64 = (1n << 64n) - 1n;

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets, indexed [x + 5*y].
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl(v, n) {
  if (n === 0) return v;
  const s = BigInt(n);
  return ((v << s) | (v >> (64n - s))) & MASK64;
}

function keccakF1600(state) {
  const C = new Array(5);
  const D = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    // theta
    for (let x = 0; x < 5; x++) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
    for (let i = 0; i < 25; i++) state[i] ^= D[i % 5];
    // rho + pi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROT[x + 5 * y]);
      }
    }
    // chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= RC[round];
  }
}

const RATE = 136; // bytes, for 256-bit output

/** keccak256(bytes: Uint8Array) -> Uint8Array(32) */
export function keccak256(input) {
  const state = new Array(25).fill(0n);
  const block = new Uint8Array(RATE);
  // Single/multi-block absorb; our inputs are short but stay correct in general.
  let offset = 0;
  while (offset + RATE <= input.length) {
    for (let i = 0; i < RATE; i++) block[i] = input[offset + i];
    absorb(state, block);
    keccakF1600(state);
    offset += RATE;
  }
  block.fill(0);
  const rem = input.length - offset;
  for (let i = 0; i < rem; i++) block[i] = input[offset + i];
  block[rem] ^= 0x01; // Keccak domain byte
  block[RATE - 1] ^= 0x80;
  absorb(state, block);
  keccakF1600(state);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const lane = state[(i / 8) | 0];
    out[i] = Number((lane >> BigInt(8 * (i % 8))) & 0xffn);
  }
  return out;
}

function absorb(state, block) {
  for (let i = 0; i < RATE; i++) {
    const laneIdx = (i / 8) | 0;
    state[laneIdx] ^= BigInt(block[i]) << BigInt(8 * (i % 8));
  }
}

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** selector("transfer(address,uint256)") -> "a9059cbb" */
export function selector(signature) {
  return bytesToHex(keccak256(new TextEncoder().encode(signature)).slice(0, 4));
}
