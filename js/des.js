/* =========================================================
   des.js — Data Encryption Standard (DES)
   Plaintext/ciphertext: 64 bit | Key: 64 bit (56 efektif)
   ========================================================= */

const DES = (() => {
  const IP = [58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6,
              64,56,48,40,32,24,16,8, 57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
              61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7];

  const IPI = [40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30,
               37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
               34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25];

  const PC1 = [57,49,41,33,25,17,9, 1,58,50,42,34,26,18, 10,2,59,51,43,35,27,
               19,11,3,60,52,44,36, 63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
               14,6,61,53,45,37,29, 21,13,5,28,20,12,4];

  const PC2 = [14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
               41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32];

  const SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

  const E = [32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
             16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1];

  const P = [16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10,
             2,8,24,14, 32,27,3,9, 19,13,30,6, 22,11,4,25];

  const SBOX = [
    [ // S1
      [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
      [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
      [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
      [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
    ],
    [ // S2
      [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
      [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
      [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
      [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
    ],
    [ // S3
      [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
      [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
      [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
      [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
    ],
    [ // S4
      [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
      [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
      [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
      [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
    ],
    [ // S5
      [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
      [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
      [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
      [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
    ],
    [ // S6
      [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
      [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
      [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
      [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
    ],
    [ // S7
      [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
      [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
      [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
      [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
    ],
    [ // S8
      [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
      [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
      [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
      [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ]
  ];

  function sbox(i, bits6) {
    const row = parseInt(bits6[0] + bits6[5], 2);
    const col = parseInt(bits6.slice(1, 5), 2);
    return SBOX[i][row][col].toString(2).padStart(4, '0');
  }

  function keySchedule(key64, steps) {
    const pc1 = permute(key64, PC1);
    let [c, d] = splitHalf(pc1);
    steps.push({
      title: 'Generate Keys — Permuted Choice 1 (PC-1)',
      html: `<p>Key 64-bit dipermutasi (mengabaikan 8 bit parity) menjadi 56-bit dengan tabel <b>PC-1</b>.</p>
        ${ioRow([{ label: 'Key (64 bit)', val: binToHex(key64), cls: 'key' }, { label: 'PC-1 (56 bit)', val: binToHex(pc1), cls: 'key' }])}
        <p>Dibagi menjadi <b>C0</b> (28 bit) dan <b>D0</b> (28 bit).</p>
        ${ioRow([{ label: 'C0', val: c }, { label: 'D0', val: d }])}`
    });

    const subkeys = [];
    let rows = [];
    for (let i = 1; i <= 16; i++) {
      c = leftShift(c, SHIFTS[i - 1]);
      d = leftShift(d, SHIFTS[i - 1]);
      const ki = permute(c + d, PC2);
      subkeys.push(ki);
      rows.push([i, SHIFTS[i - 1], binToHex(c), binToHex(d), binToHex(ki)]);
    }
    steps.push({
      title: 'Generate Keys — Left Shift tiap ronde + Permuted Choice 2 (PC-2)',
      html: `<p>Untuk tiap ronde 1–16, C dan D di-shift kiri sesuai jadwal shift standar DES, lalu digabung (Ci‖Di) dan dipermutasi dengan <b>PC-2</b> (56→48 bit) menghasilkan subkey Ki.</p>
        ${htmlTable(['Ronde','Jumlah Shift','Ci (hex)','Di (hex)','Ki (hex, 48 bit)'], rows)}
        <p class="note">Seluruh 16 subkey (K1–K16) di atas digunakan pada tiap ronde Feistel di bawah.</p>`
    });
    return subkeys;
  }

  function feistelRound(l, r, ki, roundNum, steps) {
    const er = permute(r, E);
    const x = xorBits(er, ki);
    let sOut = '';
    let sRows = [];
    for (let i = 0; i < 8; i++) {
      const chunk = x.slice(i * 6, i * 6 + 6);
      const out = sbox(i, chunk);
      sOut += out;
      sRows.push([`S${i + 1}`, chunk, out]);
    }
    const pOut = permute(sOut, P);
    const newR = xorBits(l, pOut);

    steps.push({
      title: `Ronde ${roundNum}`,
      html: `
        ${ioRow([{ label: 'L' + (roundNum - 1), val: binToHex(l) }, { label: 'R' + (roundNum - 1), val: binToHex(r) }])}
        <p>Expansion Permutation (E) terhadap R${roundNum - 1} (32→48 bit):</p>
        ${ioRow([{ label: 'E(R)', val: binToHex(er) }])}
        <p>XOR dengan subkey K${roundNum}:</p>
        ${ioRow([{ label: 'E(R)', val: binToHex(er) }, { label: `K${roundNum}`, val: binToHex(ki), cls: 'key' }, { label: 'Hasil XOR', val: binToHex(x), cls: 'out' }])}
        <p>Substitusi melalui 8 S-Box (masing-masing 6→4 bit):</p>
        ${htmlTable(['S-Box','Input (6 bit)','Output (4 bit)'], sRows)}
        <p>Gabungan output S-Box (32 bit) dipermutasi dengan tabel <b>P</b>:</p>
        ${ioRow([{ label: 'Sebelum P', val: binToHex(sOut) }, { label: 'P(...)', val: binToHex(pOut) }])}
        <p>R${roundNum} = L${roundNum - 1} ⊕ P(...); L${roundNum} = R${roundNum - 1}${roundNum < 16 ? ' (lalu swap L/R)' : ' (ronde ke-16: TIDAK swap)'}</p>
        ${ioRow([{ label: `L${roundNum}`, val: binToHex(r) }, { label: `R${roundNum}`, val: binToHex(newR), cls: 'out' }])}
      `
    });
    return [r, newR];
  }

  function run(inputBin64, keyBin64, mode, steps) {
    let subkeys = keySchedule(keyBin64, steps);
    if (mode === 'dec') subkeys = [...subkeys].reverse();

    const ip = permute(inputBin64, IP);
    steps.push({
      title: 'Initial Permutation (IP)',
      html: `<p>${mode === 'enc' ? 'Plaintext' : 'Ciphertext'} 64-bit dipermutasi dengan tabel <b>IP</b>.</p>
        ${ioRow([{ label: 'Input', val: binToHex(inputBin64) }, { label: 'IP(Input)', val: binToHex(ip), cls: 'out' }])}`
    });

    let [l, r] = splitHalf(ip);
    for (let i = 1; i <= 16; i++) {
      [l, r] = feistelRound(l, r, subkeys[i - 1], i, steps);
    }
    // setelah ronde 16: tidak swap -> gabung R16 L16 (karena feistelRound sudah mengembalikan [L,R] tanpa swap eksplisit,
    // maka preswap combine adalah L16 R16 = [r_lama, newR] -> kita pakai r+l urutan sesuai standar: gabungkan sbg R16||L16? 
    const combined = r + l; // R16 L16 (karena tidak ada swap di akhir ronde 16 -> preoutput = R16||L16)
    const finalOut = permute(combined, IPI);
    steps.push({
      title: 'Final Permutation (Gabungan L16R16 + IP⁻¹)',
      html: `<p>Setelah ronde ke-16 tidak dilakukan swap, sehingga digabung sebagai <b>R16‖L16</b>, lalu dipermutasi dengan <b>IP⁻¹</b> menjadi hasil akhir.</p>
        ${ioRow([{ label: 'R16‖L16', val: binToHex(combined) }, { label: `${mode === 'enc' ? 'Ciphertext' : 'Plaintext'} akhir`, val: binToHex(finalOut), cls: 'out' }])}`
    });
    return finalOut;
  }

  function encrypt(ptBin64, keyBin64) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Plaintext (64 bit hex)', val: binToHex(ptBin64) }, { label: 'Key (64 bit hex)', val: binToHex(keyBin64), cls: 'key' }]) });
    const result = run(ptBin64, keyBin64, 'enc', steps);
    return { result, steps };
  }

  function decrypt(ctBin64, keyBin64) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Ciphertext (64 bit hex)', val: binToHex(ctBin64) }, { label: 'Key (64 bit hex)', val: binToHex(keyBin64), cls: 'key' }]) });
    const result = run(ctBin64, keyBin64, 'dec', steps);
    return { result, steps };
  }

  return { encrypt, decrypt };
})();
