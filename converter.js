// ============================================================
// Yamaha PPF → Encrypted CPI Converter (Browser)
// ============================================================

const KNOWN_TAGS = new Set([
  'XPFH', 'XPIH', 'XMDL', 'XPID',
  'EUID', 'ETIT', 'BLOB', 'EEXT', 'EICO', 'FBIN',
  'CSEC',
]);

const textDecoder = new TextDecoder('ascii');
const utf8Decoder = new TextDecoder('utf-8');
const textEncoder = new TextEncoder();

// ---- Chunk Reader ----

function readFourCC(buf, offset) {
  return textDecoder.decode(buf.slice(offset, offset + 4));
}

function readUint32BE(buf, offset) {
  return ((buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
}

function writeUint32BE(buf, offset, value) {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function isKnownTag(buf, pos) {
  if (pos + 4 > buf.length) return false;
  return KNOWN_TAGS.has(readFourCC(buf, pos));
}

function skipToNextTag(buf, pos, end) {
  while (pos < end) {
    if (isKnownTag(buf, pos)) return pos;
    pos++;
  }
  return pos;
}

function readChunks(buf, startOffset, endOffset) {
  const end = endOffset ?? buf.length;
  const chunks = [];
  let pos = startOffset;
  while (pos + 8 <= end) {
    pos = skipToNextTag(buf, pos, end);
    if (pos + 8 > end) break;
    const id = readFourCC(buf, pos);
    if (!KNOWN_TAGS.has(id)) break;
    const size = readUint32BE(buf, pos + 4);
    const dataStart = pos + 8;
    const dataEnd = Math.min(dataStart + size, end);
    chunks.push({ id, size, data: buf.slice(dataStart, dataEnd), offset: pos });
    pos = dataEnd;
  }
  return chunks;
}

function readSubChunks(chunk) {
  return readChunks(chunk.data, 0);
}

function chunkText(chunk) {
  return utf8Decoder.decode(chunk.data).replace(/\x00/g, '');
}

// ---- Chunk Builder ----

function concatArrays(arrays) {
  const totalLen = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(totalLen);
  let pos = 0;
  for (const a of arrays) { result.set(a, pos); pos += a.length; }
  return result;
}

function buildChunk(id, data) {
  const buf = new Uint8Array(8 + data.length);
  buf.set(textEncoder.encode(id).slice(0, 4), 0);
  writeUint32BE(buf, 4, data.length);
  buf.set(data, 8);
  return buf;
}

function buildContainerChunk(id, subChunks) {
  return buildChunk(id, concatArrays(subChunks));
}

function buildTextChunk(id, text) {
  return buildChunk(id, textEncoder.encode(text + '\0'));
}

// ---- Parsers ----

function parseN27(buf) {
  function readStr(offset, maxLen) {
    let end = offset;
    while (end < offset + maxLen && buf[end] !== 0) end++;
    return textDecoder.decode(buf.slice(offset, end));
  }
  return {
    modelName: readStr(0, 64),
    serial: readStr(64, 24),
    fullId: readStr(88, 32),
  };
}

function parsePPFRaw(buf) {
  const chunks = readChunks(buf, 8);
  let uid = '';
  let title = '';
  const blobs = [];
  for (const chunk of chunks) {
    if (chunk.id === 'EUID' && !uid) uid = chunkText(chunk);
    else if (chunk.id === 'ETIT' && !title) title = chunkText(chunk);
    else if (chunk.id === 'BLOB') {
      const sub = readSubChunks(chunk);
      const entry = { uid: '', title: '', extension: '', iconCode: null, binaryData: new Uint8Array(0) };
      for (const s of sub) {
        if (s.id === 'EUID') entry.uid = chunkText(s);
        else if (s.id === 'ETIT') entry.title = chunkText(s);
        else if (s.id === 'EEXT') entry.extension = chunkText(s);
        else if (s.id === 'EICO') entry.iconCode = chunkText(s);
        else if (s.id === 'FBIN') entry.binaryData = s.data;
      }
      blobs.push(entry);
    }
  }
  return { uid, title, blobs };
}

// ============================================================
// DES Encryption (Pure JS, browser-compatible)
// 32-bit integer-based implementation with pre-computed SP-boxes
// ============================================================

// Pre-computed SP-boxes: combined S-box substitution + P-permutation.
// Each SP[i] has 64 entries. Input: 6-bit value, Output: 32-bit integer
// with the 4 S-box output bits placed at their post-P-permutation positions.
const SP1 = new Uint32Array([
  0x00808200,0x00000000,0x00008000,0x00808202,0x00808002,0x00008202,0x00000002,0x00008000,
  0x00000200,0x00808200,0x00808202,0x00000200,0x00800202,0x00808002,0x00800000,0x00000002,
  0x00000202,0x00800200,0x00800200,0x00008200,0x00008200,0x00808000,0x00808000,0x00800202,
  0x00008002,0x00800002,0x00800002,0x00008002,0x00000000,0x00000202,0x00008202,0x00800000,
  0x00008000,0x00808202,0x00000002,0x00808000,0x00808200,0x00800000,0x00800000,0x00000200,
  0x00808002,0x00008000,0x00008200,0x00800002,0x00000200,0x00000002,0x00800202,0x00008202,
  0x00808202,0x00008002,0x00808000,0x00800202,0x00800002,0x00000202,0x00008202,0x00808200,
  0x00000202,0x00800200,0x00800200,0x00000000,0x00008002,0x00008200,0x00000000,0x00808002,
]);
const SP2 = new Uint32Array([
  0x40084010,0x40004000,0x00004000,0x00084010,0x00080000,0x00000010,0x40080010,0x40004010,
  0x40000010,0x40084010,0x40084000,0x40000000,0x40004000,0x00080000,0x00000010,0x40080010,
  0x00084000,0x00080010,0x40004010,0x00000000,0x40000000,0x00004000,0x00084010,0x40080000,
  0x00080010,0x40000010,0x00000000,0x00084000,0x00004010,0x40084000,0x40080000,0x00004010,
  0x00000000,0x00084010,0x40080010,0x00080000,0x40004010,0x40080000,0x40084000,0x00004000,
  0x40080000,0x40004000,0x00000010,0x40084010,0x00084010,0x00000010,0x00004000,0x40000000,
  0x00004010,0x40084000,0x00080000,0x40000010,0x00080010,0x40004010,0x40000010,0x00080010,
  0x00084000,0x00000000,0x40004000,0x00004010,0x40000000,0x40080010,0x40084010,0x00084000,
]);
const SP3 = new Uint32Array([
  0x00000104,0x04010100,0x00000000,0x04010004,0x04000100,0x00000000,0x00010104,0x04000100,
  0x00010004,0x04000004,0x04000004,0x00010000,0x04010104,0x00010004,0x04010000,0x00000104,
  0x04000000,0x00000004,0x04010100,0x00000100,0x00010100,0x04010000,0x04010004,0x00010104,
  0x04000104,0x00010100,0x00010000,0x04000104,0x00000004,0x04010104,0x00000100,0x04000000,
  0x04010100,0x04000000,0x00010004,0x00000104,0x00010000,0x04010100,0x04000100,0x00000000,
  0x00000100,0x00010004,0x04010104,0x04000100,0x04000004,0x00000100,0x00000000,0x04010004,
  0x04000104,0x00010000,0x04000000,0x04010104,0x00000004,0x00010104,0x00010100,0x04000004,
  0x04010000,0x04000104,0x00000104,0x04010000,0x00010104,0x00000004,0x04010004,0x00010100,
]);
const SP4 = new Uint32Array([
  0x80401000,0x80001040,0x80001040,0x00000040,0x00401040,0x80400040,0x80400000,0x80001000,
  0x00000000,0x00401000,0x00401000,0x80401040,0x80000040,0x00000000,0x00400040,0x80400000,
  0x80000000,0x00001000,0x00400000,0x80401000,0x00000040,0x00400000,0x80001000,0x00001040,
  0x80400040,0x80000000,0x00001040,0x00400040,0x00001000,0x00401040,0x80401040,0x80000040,
  0x00400040,0x80400000,0x00401000,0x80401040,0x80000040,0x00000000,0x00000000,0x00401000,
  0x00001040,0x00400040,0x80400040,0x80000000,0x80401000,0x80001040,0x80001040,0x00000040,
  0x80401040,0x80000040,0x80000000,0x00001000,0x80400000,0x80001000,0x00401040,0x80400040,
  0x80001000,0x00001040,0x00400000,0x80401000,0x00000040,0x00400000,0x00001000,0x00401040,
]);
const SP5 = new Uint32Array([
  0x00000080,0x01040080,0x01040000,0x21000080,0x00040000,0x00000080,0x20000000,0x01040000,
  0x20040080,0x00040000,0x01000080,0x20040080,0x21000080,0x21040000,0x00040080,0x20000000,
  0x01000000,0x20040000,0x20040000,0x00000000,0x20000080,0x21040080,0x21040080,0x01000080,
  0x21040000,0x20000080,0x00000000,0x21000000,0x01040080,0x01000000,0x21000000,0x00040080,
  0x00040000,0x21000080,0x00000080,0x01000000,0x20000000,0x01040000,0x21000080,0x20040080,
  0x01000080,0x20000000,0x21040000,0x01040080,0x20040080,0x00000080,0x01000000,0x21040000,
  0x21040080,0x00040080,0x21000000,0x21040080,0x01040000,0x00000000,0x20040000,0x21000000,
  0x00040080,0x01000080,0x20000080,0x00040000,0x00000000,0x20040000,0x01040080,0x20000080,
]);
const SP6 = new Uint32Array([
  0x10000008,0x10200000,0x00002000,0x10202008,0x10200000,0x00000008,0x10202008,0x00200000,
  0x10002000,0x00202008,0x00200000,0x10000008,0x00200008,0x10002000,0x10000000,0x00002008,
  0x00000000,0x00200008,0x10002008,0x00002000,0x00202000,0x10002008,0x00000008,0x10200008,
  0x10200008,0x00000000,0x00202008,0x10202000,0x00002008,0x00202000,0x10202000,0x10000000,
  0x10002000,0x00000008,0x10200008,0x00202000,0x10202008,0x00200000,0x00002008,0x10000008,
  0x00200000,0x10002000,0x10000000,0x00002008,0x10000008,0x10202008,0x00202000,0x10200000,
  0x00202008,0x10202000,0x00000000,0x10200008,0x00000008,0x00002000,0x10200000,0x00202008,
  0x00002000,0x00200008,0x10002008,0x00000000,0x10202000,0x10000000,0x00200008,0x10002008,
]);
const SP7 = new Uint32Array([
  0x00100000,0x02100001,0x02000401,0x00000000,0x00000400,0x02000401,0x00100401,0x02100400,
  0x02100401,0x00100000,0x00000000,0x02000001,0x00000001,0x02000000,0x02100001,0x00000401,
  0x02000400,0x00100401,0x00100001,0x02000400,0x02000001,0x02100000,0x02100400,0x00100001,
  0x02100000,0x00000400,0x00000401,0x02100401,0x00100400,0x00000001,0x02000000,0x00100400,
  0x02000000,0x00100400,0x00100000,0x02000401,0x02000401,0x02100001,0x02100001,0x00000001,
  0x00100001,0x02000000,0x02000400,0x00100000,0x02100400,0x00000401,0x00100401,0x02100400,
  0x00000401,0x02000001,0x02100401,0x02100000,0x00100400,0x00000000,0x00000001,0x02100401,
  0x00000000,0x00100401,0x02100000,0x00000400,0x02000001,0x02000400,0x00000400,0x00100001,
]);
const SP8 = new Uint32Array([
  0x08000820,0x00000800,0x00020000,0x08020820,0x08000000,0x08000820,0x00000020,0x08000000,
  0x00020020,0x08020000,0x08020820,0x00020800,0x08020800,0x00020820,0x00000800,0x00000020,
  0x08020000,0x08000020,0x08000800,0x00000820,0x00020800,0x00020020,0x08020020,0x08020800,
  0x00000820,0x00000000,0x00000000,0x08020020,0x08000020,0x08000800,0x00020820,0x00020000,
  0x00020820,0x00020000,0x08020800,0x00000800,0x00000020,0x08020020,0x00000800,0x00020820,
  0x08000800,0x00000020,0x08000020,0x08020000,0x08020020,0x08000000,0x00020000,0x08000820,
  0x00000000,0x08020820,0x00020020,0x08000020,0x08020000,0x08000800,0x08000820,0x00000000,
  0x08020820,0x00020800,0x00020800,0x00000820,0x00000820,0x00020020,0x08000000,0x08020800,
]);

const ROTATIONS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

// --- DES Core (32-bit integer based) ---

/** Convert 8-byte block to two 32-bit integers [hi, lo] */
function bytesToLR(buf, off) {
  const L = ((buf[off]<<24)|(buf[off+1]<<16)|(buf[off+2]<<8)|buf[off+3]) >>> 0;
  const R = ((buf[off+4]<<24)|(buf[off+5]<<16)|(buf[off+6]<<8)|buf[off+7]) >>> 0;
  return [L, R];
}

/** Convert two 32-bit integers to 8 bytes in buffer */
function lrToBytes(L, R, buf, off) {
  buf[off]=(L>>>24)&0xff; buf[off+1]=(L>>>16)&0xff; buf[off+2]=(L>>>8)&0xff; buf[off+3]=L&0xff;
  buf[off+4]=(R>>>24)&0xff; buf[off+5]=(R>>>16)&0xff; buf[off+6]=(R>>>8)&0xff; buf[off+7]=R&0xff;
}

/** Initial Permutation using delta-swap decomposition */
function initialPerm(L, R) {
  // IP can be decomposed into a sequence of delta-swaps
  let t;
  t = ((L >>> 4) ^ R) & 0x0F0F0F0F; R ^= t; L ^= (t << 4);
  t = ((L >>> 16) ^ R) & 0x0000FFFF; R ^= t; L ^= (t << 16);
  t = ((R >>> 2) ^ L) & 0x33333333; L ^= t; R ^= (t << 2);
  t = ((R >>> 8) ^ L) & 0x00FF00FF; L ^= t; R ^= (t << 8);
  t = ((L >>> 1) ^ R) & 0x55555555; R ^= t; L ^= (t << 1);
  return [L >>> 0, R >>> 0];
}

/** Final Permutation (inverse of IP) using delta-swap decomposition */
function finalPerm(L, R) {
  let t;
  t = ((L >>> 1) ^ R) & 0x55555555; R ^= t; L ^= (t << 1);
  t = ((R >>> 8) ^ L) & 0x00FF00FF; L ^= t; R ^= (t << 8);
  t = ((R >>> 2) ^ L) & 0x33333333; L ^= t; R ^= (t << 2);
  t = ((L >>> 16) ^ R) & 0x0000FFFF; R ^= t; L ^= (t << 16);
  t = ((L >>> 4) ^ R) & 0x0F0F0F0F; R ^= t; L ^= (t << 4);
  return [L >>> 0, R >>> 0];
}

/** Generate 16 subkeys from 8-byte key. Each subkey is [hi28, lo28] packed as [k0, k1]. */
function generateSubKeys(keyBytes) {
  // PC-1: extract 56 bits from 64-bit key
  // Split into C (bits 57,49,...,36) and D (bits 63,55,...,4)
  // Implemented via bit extraction from key bytes
  const k = keyBytes;

  // Extract 28-bit C and D halves after PC-1
  // PC-1 left half (C0): bits 57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36
  // PC-1 right half (D0): bits 63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
  // We extract these using a general bit-extraction approach
  function getBit64(bit1based) {
    const byteIdx = (bit1based - 1) >>> 3;
    const bitIdx = 7 - ((bit1based - 1) & 7);
    return (k[byteIdx] >>> bitIdx) & 1;
  }

  const PC1_C = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36];
  const PC1_D = [63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];

  let C = 0, D = 0;
  for (let i = 0; i < 28; i++) {
    C = (C | (getBit64(PC1_C[i]) << (27 - i))) >>> 0;
    D = (D | (getBit64(PC1_D[i]) << (27 - i))) >>> 0;
  }

  // PC-2 table (1-based within the 56-bit CD, selecting 48 bits)
  const PC2 = [
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32,
  ];

  const subKeys = [];
  for (let round = 0; round < 16; round++) {
    // Left rotate C and D by ROTATIONS[round]
    const r = ROTATIONS[round];
    C = ((C << r) | (C >>> (28 - r))) & 0x0FFFFFFF;
    D = ((D << r) | (D >>> (28 - r))) & 0x0FFFFFFF;

    // Combine C and D into 56-bit value and apply PC-2
    // CD bit i (1-based): bits 1-28 from C, bits 29-56 from D
    function getBitCD(bit1based) {
      if (bit1based <= 28) {
        return (C >>> (28 - bit1based)) & 1;
      } else {
        return (D >>> (56 - bit1based)) & 1;
      }
    }

    // Extract 48-bit subkey as two 24-bit halves packed into [hi, lo]
    let kHi = 0, kLo = 0;
    for (let i = 0; i < 24; i++) {
      kHi = (kHi | (getBitCD(PC2[i]) << (23 - i))) >>> 0;
    }
    for (let i = 0; i < 24; i++) {
      kLo = (kLo | (getBitCD(PC2[24 + i]) << (23 - i))) >>> 0;
    }
    subKeys.push([kHi, kLo]);
  }
  return subKeys;
}

/** DES F function: takes 32-bit R and subkey [kHi24, kLo24], returns 32-bit result */
function desF(R, K) {
  // Expansion E is done implicitly by extracting 6-bit groups from R
  // R bits are numbered 1-32 (MSB=1). E expands to 48 bits.
  // We extract the 8 six-bit groups and XOR with key.
  //
  // E expansion pattern (each group uses specific bits of R):
  // Group 0: bits 32, 1, 2, 3, 4, 5
  // Group 1: bits  4, 5, 6, 7, 8, 9
  // Group 2: bits  8, 9,10,11,12,13
  // Group 3: bits 12,13,14,15,16,17
  // Group 4: bits 16,17,18,19,20,21
  // Group 5: bits 20,21,22,23,24,25
  // Group 6: bits 24,25,26,27,28,29
  // Group 7: bits 28,29,30,31,32, 1

  // Extract 6-bit groups from R (R is 32-bit, bit 1 = bit 31 in integer)
  const e0 = ((R << 1) & 0x3E) | ((R >>> 31) & 1);  // bits 32,1,2,3,4,5
  const e1 = (R >>> 27) & 0x3F;                       // bits 4,5,6,7,8,9... wait, need to be more careful

  // Actually, let me use a cleaner approach. R as 32-bit integer:
  // bit 1 (MSB) is at position 31, bit 32 (LSB) is at position 0
  // E group i takes specific bits. Let's compute each:

  const r = R; // alias
  // For each 6-bit group, we need: outer_bits give row, inner 4 bits give column
  // But for SP-box lookup, we just need the 6-bit value (row/col extraction is pre-baked into SP tables)

  // Expand R to 48 bits as 8 groups of 6 bits
  // E-bit positions (1-based in 32-bit R):
  // G0: 32, 1, 2, 3, 4, 5 → r bits at positions 0,31,30,29,28,27
  // G1:  4, 5, 6, 7, 8, 9 → r bits at positions 28,27,26,25,24,23
  // G2:  8, 9,10,11,12,13 → r bits at positions 24,23,22,21,20,19
  // G3: 12,13,14,15,16,17 → r bits at positions 20,19,18,17,16,15
  // G4: 16,17,18,19,20,21 → r bits at positions 16,15,14,13,12,11
  // G5: 20,21,22,23,24,25 → r bits at positions 12,11,10, 9, 8, 7
  // G6: 24,25,26,27,28,29 → r bits at positions  8, 7, 6, 5, 4, 3
  // G7: 28,29,30,31,32, 1 → r bits at positions  4, 3, 2, 1, 0,31

  const g0 = (((r & 1) << 5) | ((r >>> 27) & 0x1F)) ^ (K[0] >>> 18);
  const g1 = ((r >>> 23) & 0x3F) ^ ((K[0] >>> 12) & 0x3F);
  const g2 = ((r >>> 19) & 0x3F) ^ ((K[0] >>> 6) & 0x3F);
  const g3 = ((r >>> 15) & 0x3F) ^ (K[0] & 0x3F);
  const g4 = ((r >>> 11) & 0x3F) ^ (K[1] >>> 18);
  const g5 = ((r >>> 7) & 0x3F) ^ ((K[1] >>> 12) & 0x3F);
  const g6 = ((r >>> 3) & 0x3F) ^ ((K[1] >>> 6) & 0x3F);
  const g7 = ((((r & 0x1F) << 1) | ((r >>> 31) & 1)) ^ (K[1] & 0x3F)) & 0x3F;

  // SP-box lookups (combined S-box + P-permutation)
  return (SP1[g0] ^ SP2[g1] ^ SP3[g2] ^ SP4[g3] ^ SP5[g4] ^ SP6[g5] ^ SP7[g6] ^ SP8[g7]) >>> 0;
}

/** Encrypt a single 8-byte block with DES ECB */
function desBlock(block, subKeys) {
  let [L, R] = bytesToLR(block, 0);
  [L, R] = initialPerm(L, R);

  for (let i = 0; i < 16; i++) {
    const f = desF(R, subKeys[i]);
    const newR = (L ^ f) >>> 0;
    L = R;
    R = newR;
  }

  // Swap and apply final permutation
  [L, R] = finalPerm(R, L);

  const out = new Uint8Array(8);
  lrToBytes(L, R, out, 0);
  return out;
}

// --- DES Key & Encryption ---

function msbParity(keyBytes) {
  const result = new Uint8Array(keyBytes.length);
  for (let i = 0; i < keyBytes.length; i++) {
    let b = keyBytes[i] & 0x7F;
    let t = b;
    t ^= (t << 4) & 0xFF;
    t ^= (t << 2) & 0xFF;
    t ^= (t << 1) & 0xFF;
    result[i] = b | (~t & 0x80);
  }
  return result;
}

function encryptDES_CBC(data, keyBytes, iv) {
  const key = msbParity(keyBytes);
  const subKeys = generateSubKeys(key);
  const encrypted = new Uint8Array(data.length);
  const prevBlock = new Uint8Array(iv);

  for (let i = 0; i < data.length; i += 8) {
    const block = new Uint8Array(8);
    for (let j = 0; j < 8; j++) block[j] = data[i + j] ^ prevBlock[j];
    const enc = desBlock(block, subKeys);
    encrypted.set(enc, i);
    prevBlock.set(enc);
  }
  return encrypted;
}

function addYamahaPadding(data) {
  const remainder = data.length % 8;
  const padLen = remainder === 0 ? 8 : 8 - remainder;
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data, 0);
  padded[padded.length - 1] = remainder;
  return padded;
}

// ---- Constants ----

const DES_KEY = new Uint8Array([0x46, 0x6f, 0x61, 0x74, 0x66, 0x6b, 0x69, 0x6f]); // "Foatfkio"
const DES_IV = new Uint8Array(8); // 8 zero bytes
const DES_KEY_DUALSEAL = new Uint8Array([0x64, 0x75, 0x61, 0x6C, 0x73, 0x65, 0x61, 0x6C]); // "dualseal"

const XOR_SEED = new Uint8Array([
  0x0F, 0x62, 0xBE, 0x39, 0xD1, 0x70, 0xC7, 0xF4,
  0x1A, 0x85, 0x2D, 0x5C, 0x96, 0xE8, 0x4B, 0xA3,
]);

const EXPANSION_TABLE = [
  0x07, 0x0C, 0x0E, 0x0A, 0x0B, 0x0D, 0x00, 0x01,
  0x06, 0x02, 0x0F, 0x03, 0x09, 0x04, 0x08, 0x05,
  0x00, 0x0F, 0x02, 0x08, 0x06, 0x09, 0x01, 0x0A,
  0x0E, 0x0C, 0x0B, 0x03, 0x04, 0x05, 0x07, 0x0D,
  0x07, 0x05, 0x0C, 0x04, 0x0F, 0x0D, 0x01, 0x09,
  0x08, 0x0A, 0x00, 0x03, 0x0B, 0x06, 0x0E, 0x02,
];

// Standard CSEC encrypted authentication data (80 bytes)
const CSEC_ENCRYPTED = new Uint8Array([
  0x5a,0x51,0x7c,0x40,0x5f,0x44,0x7c,0x02,
  0x90,0x3b,0xcc,0x5e,0x1d,0x69,0xdc,0xf8,
  0x52,0x2f,0xe8,0x75,0xd0,0xed,0x7f,0x97,
  0xf3,0xef,0x1e,0x23,0x6e,0x4f,0x9d,0x80,
  0x29,0x87,0x42,0x89,0xad,0xdc,0xc3,0xc2,
  0x23,0xff,0xa3,0x65,0x55,0xc2,0x5d,0xaf,
  0xf4,0x93,0x11,0x96,0xf1,0x4d,0xa7,0xd9,
  0x12,0xe6,0x07,0xee,0x15,0xc0,0x45,0x24,
  0x26,0x58,0x5c,0x1f,0xb4,0x50,0x56,0xe7,
  0x54,0xbc,0xe9,0x49,0xf6,0xda,0xf0,0x55,
]);

// ---- Device Lock Crypto (IDA: sub_14095DFD0, sub_14095E300, sub_14095E550) ----

function keyDerivation(inputString) {
  const src = typeof inputString === 'string'
    ? textEncoder.encode(inputString)
    : inputString;
  let length = src.length;
  if (length === 0) return null;
  if (length > 128) length = 128;

  const buf = new Uint8Array(128);
  buf.set(src.slice(0, length));

  const output = new Uint8Array(16);
  if (length >= 16) {
    for (let i = 0; i < 16; i++) {
      let val = 0;
      for (let chunk = 0; chunk < 8; chunk++) {
        val ^= buf[chunk * 16 + i];
      }
      output[i] = val;
    }
  } else {
    for (let i = 0; i < length; i++) output[i] = src[i];
    for (let j = 0; j < 16 - length; j++) {
      output[length + j] = XOR_SEED[length + j] ^ src[j % length];
    }
  }
  return output;
}

function keyExpansion(key16) {
  const output = new Uint8Array(24);
  for (let r = 0; r < 3; r++) {
    for (let j = 0; j < 8; j++) {
      const idx1 = EXPANSION_TABLE[2 * j + r * 16];
      const idx2 = EXPANSION_TABLE[2 * j + 1 + r * 16];
      output[r * 8 + j] = key16[idx1] ^ key16[idx2];
    }
  }
  return output;
}

function desDecryptBlock(block, subKeys) {
  let [L, R] = bytesToLR(block, 0);
  [L, R] = initialPerm(L, R);
  for (let i = 15; i >= 0; i--) {
    const f = desF(R, subKeys[i]);
    const newR = (L ^ f) >>> 0;
    L = R;
    R = newR;
  }
  [L, R] = finalPerm(R, L);
  const out = new Uint8Array(8);
  lrToBytes(L, R, out, 0);
  return out;
}

function tripleDesEncryptCBC(data, key24) {
  const sk1 = generateSubKeys(msbParity(key24.slice(0, 8)));
  const sk2 = generateSubKeys(msbParity(key24.slice(8, 16)));
  const sk3 = generateSubKeys(msbParity(key24.slice(16, 24)));
  const encrypted = new Uint8Array(data.length);
  const prev = new Uint8Array(8);

  for (let i = 0; i < data.length; i += 8) {
    const block = new Uint8Array(8);
    for (let j = 0; j < 8; j++) block[j] = data[i + j] ^ prev[j];
    // 3DES-EDE: E_K3(D_K2(E_K1(block)))
    const step1 = desBlock(block, sk1);
    const step2 = desDecryptBlock(step1, sk2);
    const step3 = desBlock(step2, sk3);
    encrypted.set(step3, i);
    prev.set(step3);
  }
  return encrypted;
}

function generateLockedCSEC(deviceFullId) {
  const keySlot = keyDerivation(deviceFullId);
  if (!keySlot) throw new Error('Empty device key');

  // Random first_data (16 bytes)
  const firstData = new Uint8Array(16);
  crypto.getRandomValues(firstData);

  // second_data[j] = (keySlot[j] + firstData[15-j]) & 0xFF
  const secondData = new Uint8Array(16);
  for (let j = 0; j < 16; j++) {
    secondData[j] = (keySlot[j] + firstData[15 - j]) & 0xFF;
  }

  // AIRI = DES_encrypt("dualseal", yamaha_pad(firstData)) → 24 bytes
  const firstDataPadded = addYamahaPadding(firstData);
  const airi = encryptDES_CBC(firstDataPadded, DES_KEY_DUALSEAL, DES_IV);

  // AIVF = 3DES_encrypt(expand(keySlot), secondData) → 16 bytes
  const key24 = keyExpansion(keySlot);
  const aivf = tripleDesEncryptCBC(secondData, key24);

  // Build CSEC: ABCF(00 01) + ABEI(AIRI + AIVF)
  const abcf = buildChunk('ABCF', new Uint8Array([0x00, 0x01]));
  const airiChunk = buildChunk('AIRI', airi);
  const aivfChunk = buildChunk('AIVF', aivf);
  const abei = buildChunk('ABEI', concatArrays([airiChunk, aivfChunk]));
  const csecPlaintext = concatArrays([abcf, abei]);

  // DES encrypt with "Foatfkio" + Yamaha padding → 80 bytes
  const csecPadded = addYamahaPadding(csecPlaintext);
  return encryptDES_CBC(csecPadded, DES_KEY, DES_IV);
}

// ---- Encrypted CPI Builder ----

function buildEncryptedCPI(packData, modelName, packInstallId, deviceFullId) {
  // 1. XPIH header (unencrypted)
  const xmdlChunk = buildTextChunk('XMDL', modelName);
  const xpidData = new Uint8Array(4);
  writeUint32BE(xpidData, 0, packInstallId);
  const xpidChunk = buildChunk('XPID', xpidData);
  const xpihChunk = buildContainerChunk('XPIH', [xmdlChunk, xpidChunk]);

  // 2. CSEC chunk — device-locked if fullId provided, otherwise standard
  const csecData = deviceFullId ? generateLockedCSEC(deviceFullId) : CSEC_ENCRYPTED;
  const csecChunk = buildChunk('CSEC', csecData);

  // 3. Build payload (plaintext)
  const payloadParts = [];
  payloadParts.push(buildTextChunk('EUID', packData.uid));
  payloadParts.push(buildTextChunk('ETIT', packData.title));

  for (const blob of packData.blobs) {
    const blobParts = [];
    blobParts.push(buildTextChunk('EUID', blob.uid));
    blobParts.push(buildTextChunk('ETIT', blob.title));
    blobParts.push(buildTextChunk('EEXT', blob.extension));
    if (blob.iconCode) blobParts.push(buildTextChunk('EICO', blob.iconCode));
    blobParts.push(buildChunk('FBIN', blob.binaryData));
    payloadParts.push(buildContainerChunk('BLOB', blobParts));
  }

  const payloadRaw = concatArrays(payloadParts);

  // 4. Pad and encrypt payload
  const payloadPadded = addYamahaPadding(payloadRaw);
  const payloadEncrypted = encryptDES_CBC(payloadPadded, DES_KEY, DES_IV);

  // 5. Assemble: XPIH + CSEC + encrypted payload
  return concatArrays([xpihChunk, csecChunk, payloadEncrypted]);
}

// ---- Utility ----

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ---- Public API ----

window.PpiCpiConverter = { parseN27, parsePPFRaw, buildEncryptedCPI, formatFileSize, generateLockedCSEC, keyDerivation };
