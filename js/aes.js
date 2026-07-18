/* =========================================================
   aes.js — Advanced Encryption Standard (AES-128)
   Plaintext/ciphertext: 128 bit (state 4x4 byte) | Key: 128 bit
   ========================================================= */

const AES = (() => {
  const SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ];
  const INV_SBOX = new Array(256);
  SBOX.forEach((v, i) => INV_SBOX[v] = i);

  const RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36];

  const hx = n => n.toString(16).padStart(2, '0').toUpperCase();

  function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xFF;
      if (hi) a ^= 0x1B;
      b >>= 1;
    }
    return p;
  }

  function bytesToState(bytes) {
    // column-major: state[r][c] = bytes[c*4+r]
    const s = [[],[],[],[]];
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r][c] = bytes[c * 4 + r];
    return s;
  }
  function stateToBytes(s) {
    const b = [];
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) b.push(s[r][c]);
    return b;
  }
  function stateFlat(s) {
    const arr = [];
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) arr.push(hx(s[r][c]));
    return arr;
  }
  function stateMatrixHtml(s, cls) {
    return matrixHtml(stateFlat(s).map(v => cls ? `<span class="${cls}">${v}</span>` : v), 4, 4);
  }

  function hexToBytes(hex) {
    const b = [];
    for (let i = 0; i < hex.length; i += 2) b.push(parseInt(hex.substr(i, 2), 16));
    return b;
  }
  function bytesToHex(bytes) { return bytes.map(hx).join(''); }

  // ---------- Key Expansion ----------
  function keyExpansion(keyBytes, steps) {
    const w = [];
    for (let i = 0; i < 4; i++) w.push(keyBytes.slice(i * 4, i * 4 + 4));

    let rows = [];
    for (let i = 4; i < 44; i++) {
      let temp = w[i - 1].slice();
      let note = '';
      if (i % 4 === 0) {
        const rot = temp.slice(1).concat(temp.slice(0, 1));
        const sub = rot.map(b => SBOX[b]);
        const rcon = [RCON[i / 4 - 1], 0, 0, 0];
        temp = sub.map((b, idx) => b ^ rcon[idx]);
        note = `RotWord→SubWord→XOR Rcon[${i / 4}]=${hx(RCON[i / 4 - 1])}`;
      } else {
        note = 'w[i-1] langsung (tanpa transformasi)';
      }
      const wi = w[i - 4].map((b, idx) => b ^ temp[idx]);
      w.push(wi);
      rows.push([`w${i}`, bytesToHex(w[i - 4]), bytesToHex(temp), bytesToHex(wi), note]);
    }
    steps.push({
      title: 'Key Expansion — Membentuk 11 Round Key (W0–W43)',
      html: `<p>Key 128-bit dipecah menjadi 4 word (w0–w3). Setiap word baru wi = w[i-4] ⊕ temp, di mana untuk i kelipatan 4, temp dihasilkan dari RotWord, SubWord (S-Box), lalu XOR dengan konstanta Rcon; selain itu temp = w[i-1].</p>
        ${htmlTable(['Word','w[i-4]','temp','wi = w[i-4]⊕temp','Keterangan'], rows)}
        <p class="note">Setiap 4 word berurutan (w0–w3, w4–w7, ..., w40–w43) membentuk Round Key 0 sampai Round Key 10.</p>`
    });

    const roundKeys = [];
    for (let r = 0; r < 11; r++) {
      const bytes = [].concat(...w.slice(r * 4, r * 4 + 4));
      roundKeys.push(bytesToState(bytes));
    }
    return roundKeys;
  }

  function subBytes(s, inv) {
    const out = [[],[],[],[]];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r][c] = (inv ? INV_SBOX : SBOX)[s[r][c]];
    return out;
  }
  function shiftRows(s, inv) {
    const out = [[],[],[],[]];
    for (let r = 0; r < 4; r++) {
      const shift = inv ? (4 - r) % 4 : r;
      for (let c = 0; c < 4; c++) out[r][c] = s[r][(c + shift) % 4];
    }
    return out;
  }
  function mixColumns(s, inv) {
    const M = inv ? [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]
                  : [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]];
    const out = [[],[],[],[]];
    for (let c = 0; c < 4; c++) {
      const col = [s[0][c], s[1][c], s[2][c], s[3][c]];
      for (let r = 0; r < 4; r++) {
        out[r][c] = M[r].reduce((acc, m, k) => acc ^ gmul(m, col[k]), 0);
      }
    }
    return out;
  }
  function addRoundKey(s, rk) {
    const out = [[],[],[],[]];
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r][c] = s[r][c] ^ rk[r][c];
    return out;
  }

  function stateStepBlock(label, s, cls) {
    return `<p>${label}</p>${stateMatrixHtml(s, cls)}`;
  }

  function run(inputHex, keyHex, mode, steps) {
    const state0 = bytesToState(hexToBytes(inputHex));
    const roundKeys = keyExpansion(hexToBytes(keyHex), steps);
    const rks = mode === 'enc' ? roundKeys : [...roundKeys].reverse();

    let state = addRoundKey(state0, rks[0]);
    steps.push({
      title: 'Initial Round — AddRoundKey (dengan Round Key 0)',
      html: `${stateStepBlock(`State awal (${mode === 'enc' ? 'plaintext' : 'ciphertext'}):`, state0)}
        ${stateStepBlock('Round Key 0:', rks[0], 'k')}
        ${stateStepBlock('Hasil AddRoundKey:', state, 'o')}`
    });

    if (mode === 'enc') {
      for (let round = 1; round <= 9; round++) {
        const s1 = subBytes(state, false);
        const s2 = shiftRows(s1, false);
        const s3 = mixColumns(s2, false);
        const s4 = addRoundKey(s3, rks[round]);
        steps.push({
          title: `Ronde ${round}`,
          html: `${stateStepBlock('SubBytes:', s1)}${stateStepBlock('ShiftRows:', s2)}${stateStepBlock('MixColumns:', s3)}
            ${stateStepBlock(`Round Key ${round}:`, rks[round], 'k')}${stateStepBlock('AddRoundKey:', s4, 'o')}`
        });
        state = s4;
      }
      const s1 = subBytes(state, false);
      const s2 = shiftRows(s1, false);
      const s3 = addRoundKey(s2, rks[10]);
      steps.push({
        title: 'Ronde 10 (Ronde Terakhir — tanpa MixColumns)',
        html: `${stateStepBlock('SubBytes:', s1)}${stateStepBlock('ShiftRows:', s2)}
          ${stateStepBlock('Round Key 10:', rks[10], 'k')}${stateStepBlock('AddRoundKey:', s3, 'o')}`
      });
      state = s3;
    } else {
      for (let round = 1; round <= 9; round++) {
        const s1 = shiftRows(state, true);
        const s2 = subBytes(s1, true);
        const s3 = addRoundKey(s2, rks[round]);
        const s4 = mixColumns(s3, true);
        steps.push({
          title: `Ronde ${round} (Dekripsi)`,
          html: `${stateStepBlock('InvShiftRows:', s1)}${stateStepBlock('InvSubBytes:', s2)}
            ${stateStepBlock(`Round Key ${round}:`, rks[round], 'k')}${stateStepBlock('AddRoundKey:', s3)}
            ${stateStepBlock('InvMixColumns:', s4, 'o')}`
        });
        state = s4;
      }
      const s1 = shiftRows(state, true);
      const s2 = subBytes(s1, true);
      const s3 = addRoundKey(s2, rks[10]);
      steps.push({
        title: 'Ronde 10 (Dekripsi, Ronde Terakhir — tanpa InvMixColumns)',
        html: `${stateStepBlock('InvShiftRows:', s1)}${stateStepBlock('InvSubBytes:', s2)}
          ${stateStepBlock('Round Key 10:', rks[10], 'k')}${stateStepBlock('AddRoundKey:', s3, 'o')}`
      });
      state = s3;
    }

    const outHex = bytesToHex(stateToBytes(state));
    steps.push({
      title: 'Hasil Akhir',
      html: `<p>State akhir dikonversi kembali menjadi urutan byte lalu menjadi hex 128-bit.</p>
        ${ioRow([{ label: `${mode === 'enc' ? 'Ciphertext' : 'Plaintext'} (hex)`, val: outHex, cls: 'out' }])}`
    });
    return outHex;
  }

  function encrypt(ptHex, keyHex) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Plaintext (128 bit hex)', val: ptHex }, { label: 'Key (128 bit hex)', val: keyHex, cls: 'key' }]) });
    const result = run(ptHex, keyHex, 'enc', steps);
    return { result, steps };
  }
  function decrypt(ctHex, keyHex) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Ciphertext (128 bit hex)', val: ctHex }, { label: 'Key (128 bit hex)', val: keyHex, cls: 'key' }]) });
    const result = run(ctHex, keyHex, 'dec', steps);
    return { result, steps };
  }

  return { encrypt, decrypt };
})();
