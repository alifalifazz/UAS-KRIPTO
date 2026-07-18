/* =========================================================
   saes.js — Simplified AES (S-AES)
   Plaintext/ciphertext: 16 bit (state 2x2 nibble) | Key: 16 bit
   ========================================================= */

const SAES = (() => {
  // S-Box S-AES (indeks nibble 0..15)
  const SBOX = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7];
  const INV_SBOX = new Array(16);
  SBOX.forEach((v, i) => INV_SBOX[v] = i);

  const RCON1 = 0x80, RCON2 = 0x30; // dalam 8-bit (2 nibble)

  const hx1 = n => n.toString(16).toUpperCase();

  // GF(2^4) mult dengan modulus x^4+x+1 (0x13)
  function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 4; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x8;
      a = (a << 1) & 0xF;
      if (hi) a ^= 0x3; // x^4 = x+1 -> reduksi dengan 0b0011
      b >>= 1;
    }
    return p & 0xF;
  }

  function nibbles(byte) { return [(byte >> 4) & 0xF, byte & 0xF]; }
  function toByte(hiNib, loNib) { return ((hiNib & 0xF) << 4) | (loNib & 0xF); }

  function subWordNibbles(byte) {
    const [h, l] = nibbles(byte);
    return toByte(SBOX[h], SBOX[l]);
  }
  function rotWord(byte) {
    const [h, l] = nibbles(byte);
    return toByte(l, h);
  }

  function bytesToState(b0, b1) {
    // state 2x2: kolom-major -> s0 s2 / s1 s3, dengan b0=w0(s0,s1), b1=w1(s2,s3)
    const [s0, s1] = nibbles(b0);
    const [s2, s3] = nibbles(b1);
    return [[s0, s2], [s1, s3]];
  }
  function stateToHex(s) {
    return [s[0][0], s[1][0], s[0][1], s[1][1]].map(hx1).join('');
  }
  function stateFlatHex(s, cls) {
    const arr = [s[0][0], s[0][1], s[1][0], s[1][1]].map(hx1);
    return matrixHtml(cls ? arr.map(v => `<span class="${cls}">${v}</span>`) : arr, 2, 2, { rowMajor: true });
  }

  function keyExpansion(keyHex, steps) {
    const keyByte0 = parseInt(keyHex.slice(0, 2), 16);
    const keyByte1 = parseInt(keyHex.slice(2, 4), 16);
    const w0 = keyByte0, w1 = keyByte1;

    const g = (w, rcon) => subWordNibbles(rotWord(w)) ^ rcon;

    const gw1 = g(w1, RCON1);
    const w2 = w0 ^ gw1;
    const w3 = w2 ^ w1;
    steps.push({
      title: 'Key Expansion — Membentuk K1 (w2, w3)',
      html: `<p>w0 = ${hx1(w0)}, w1 = ${hx1(w1)} (masing-masing 8 bit dari key 16-bit).</p>
        <p>g(w1) = SubNib(RotNib(w1)) ⊕ RCON1(${hx1(RCON1)}):</p>
        ${ioRow([{ label: 'RotNib(w1)', val: hx1(rotWord(w1)) }, { label: 'SubNib(...)', val: hx1(subWordNibbles(rotWord(w1))) }, { label: 'g(w1)', val: hx1(gw1) }])}
        ${ioRow([{ label: 'w2 = w0 ⊕ g(w1)', val: hx1(w2), cls: 'key' }, { label: 'w3 = w2 ⊕ w1', val: hx1(w3), cls: 'key' }])}
        <p><b>K1</b> = w2‖w3 = ${hx1(w2)}${hx1(w3)}</p>`
    });

    const gw3 = g(w3, RCON2);
    const w4 = w2 ^ gw3;
    const w5 = w4 ^ w3;
    steps.push({
      title: 'Key Expansion — Membentuk K2 (w4, w5)',
      html: `<p>g(w3) = SubNib(RotNib(w3)) ⊕ RCON2(${hx1(RCON2)}):</p>
        ${ioRow([{ label: 'RotNib(w3)', val: hx1(rotWord(w3)) }, { label: 'SubNib(...)', val: hx1(subWordNibbles(rotWord(w3))) }, { label: 'g(w3)', val: hx1(gw3) }])}
        ${ioRow([{ label: 'w4 = w2 ⊕ g(w3)', val: hx1(w4), cls: 'key' }, { label: 'w5 = w4 ⊕ w3', val: hx1(w5), cls: 'key' }])}
        <p><b>K2</b> = w4‖w5 = ${hx1(w4)}${hx1(w5)}</p>`
    });

    return {
      K0: bytesToState(w0, w1),
      K1: bytesToState(w2, w3),
      K2: bytesToState(w4, w5)
    };
  }

  function subNib(s, inv) {
    const box = inv ? INV_SBOX : SBOX;
    return [[box[s[0][0]], box[s[0][1]]], [box[s[1][0]], box[s[1][1]]]];
  }
  function shiftRows(s) {
    // tukar baris kedua (s[1][0] <-> s[1][1])
    return [[s[0][0], s[0][1]], [s[1][1], s[1][0]]];
  }
  function mixColumns(s, inv) {
    const M = inv ? [[9,2],[2,9]] : [[1,4],[4,1]];
    const out = [[0,0],[0,0]];
    for (let c = 0; c < 2; c++) {
      const col = [s[0][c], s[1][c]];
      out[0][c] = gmul(M[0][0], col[0]) ^ gmul(M[0][1], col[1]);
      out[1][c] = gmul(M[1][0], col[0]) ^ gmul(M[1][1], col[1]);
    }
    return out;
  }
  function addRoundKey(s, k) {
    return [[s[0][0] ^ k[0][0], s[0][1] ^ k[0][1]], [s[1][0] ^ k[1][0], s[1][1] ^ k[1][1]]];
  }

  function block(label, s, cls) {
    return `<p>${label}</p>${stateFlatHex(s, cls)}`;
  }

  function run(inputHex, keyHex, mode, steps) {
    const b0 = parseInt(inputHex.slice(0, 2), 16), b1 = parseInt(inputHex.slice(2, 4), 16);
    const state0 = bytesToState(b0, b1);
    const { K0, K1, K2 } = keyExpansion(keyHex, steps);

    const initKey = mode === 'enc' ? K0 : K2;
    const initKeyLabel = mode === 'enc' ? 'K0' : 'K2';
    let state = addRoundKey(state0, initKey);
    steps.push({
      title: `Initial Round — AddRoundKey (State ⊕ ${initKeyLabel})`,
      html: `${block(`State awal (${mode === 'enc' ? 'plaintext' : 'ciphertext'}):`, state0)}
        ${block(`${initKeyLabel}:`, initKey, 'k')}${block('Hasil:', state, 'o')}`
    });

    if (mode === 'enc') {
      const s1 = subNib(state, false);
      const s2 = shiftRows(s1);
      const s3 = mixColumns(s2, false);
      const s4 = addRoundKey(s3, K1);
      steps.push({
        title: 'Ronde 1 — SubNib, ShiftRows, MixColumns, AddRoundKey(K1)',
        html: `${block('SubNib:', s1)}${block('ShiftRows:', s2)}${block('MixColumns:', s3)}
          ${block('K1:', K1, 'k')}${block('AddRoundKey:', s4, 'o')}`
      });
      const s5 = subNib(s4, false);
      const s6 = shiftRows(s5);
      const s7 = addRoundKey(s6, K2);
      steps.push({
        title: 'Ronde 2 — SubNib, ShiftRows, AddRoundKey(K2) — tanpa MixColumns',
        html: `${block('SubNib:', s5)}${block('ShiftRows:', s6)}
          ${block('K2:', K2, 'k')}${block('AddRoundKey:', s7, 'o')}`
      });
      state = s7;
    } else {
      const s1 = shiftRows(state);
      const s2 = subNib(s1, true);
      const s3 = addRoundKey(s2, K1);
      const s4 = mixColumns(s3, true);
      steps.push({
        title: 'Ronde 1 (Dekripsi) — InvShiftRows, InvSubNib, AddRoundKey(K1), InvMixColumns',
        html: `${block('InvShiftRows:', s1)}${block('InvSubNib:', s2)}
          ${block('K1:', K1, 'k')}${block('AddRoundKey:', s3)}${block('InvMixColumns:', s4, 'o')}`
      });
      const s5 = shiftRows(s4);
      const s6 = subNib(s5, true);
      const s7 = addRoundKey(s6, K0);
      steps.push({
        title: 'Ronde 2 (Dekripsi) — InvShiftRows, InvSubNib, AddRoundKey(K0)',
        html: `${block('InvShiftRows:', s5)}${block('InvSubNib:', s6)}
          ${block('K0:', K0, 'k')}${block('AddRoundKey:', s7, 'o')}`
      });
      state = s7;
    }

    const outHex = stateToHex(state);
    steps.push({
      title: 'Hasil Akhir',
      html: `<p>State akhir dikonversi kembali menjadi 16-bit hex.</p>
        ${ioRow([{ label: `${mode === 'enc' ? 'Ciphertext' : 'Plaintext'} (hex)`, val: outHex, cls: 'out' }])}`
    });
    return outHex;
  }

  function encrypt(ptHex, keyHex) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Plaintext (16 bit hex)', val: ptHex }, { label: 'Key (16 bit hex)', val: keyHex, cls: 'key' }]) });
    const result = run(ptHex, keyHex, 'enc', steps);
    return { result, steps };
  }
  function decrypt(ctHex, keyHex) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Ciphertext (16 bit hex)', val: ctHex }, { label: 'Key (16 bit hex)', val: keyHex, cls: 'key' }]) });
    const result = run(ctHex, keyHex, 'dec', steps);
    return { result, steps };
  }

  return { encrypt, decrypt };
})();
