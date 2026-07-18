/* =========================================================
   sdes.js — Simplified DES (S-DES)
   Plaintext/ciphertext: 8 bit | Key: 10 bit
   ========================================================= */

const SDES = (() => {
  const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
  const P8  = [6, 3, 7, 4, 8, 5, 10, 9];
  const IP  = [2, 6, 3, 1, 4, 8, 5, 7];
  const IPI = [4, 1, 3, 5, 7, 2, 8, 6]; // IP^-1
  const EP  = [4, 1, 2, 3, 2, 3, 4, 1];
  const P4  = [2, 4, 3, 1];

  const S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
  ];
  const S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
  ];

  function sboxLookup(box, bits4) {
    const row = parseInt(bits4[0] + bits4[3], 2);
    const col = parseInt(bits4[1] + bits4[2], 2);
    return box[row][col].toString(2).padStart(2, '0');
  }

  // ---------- Key schedule ----------
  function keySchedule(key10, steps) {
    const p10 = permute(key10, P10);
    const [l0, r0] = splitHalf(p10);
    steps.push({
      title: 'Generate Keys — Permutasi P10',
      html: `<p>Kunci 10-bit dipermutasi menggunakan tabel <b>P10</b> = [${P10.join(',')}].</p>
        ${ioRow([{ label: 'Key awal (10 bit)', val: miniBits(key10), cls: 'key' },
                 { label: 'Hasil P10', val: miniBits(p10), cls: 'key' }])}
        <p>P10 dibagi dua: <b>L0</b> = ${l0}, <b>R0</b> = ${r0}</p>`
    });

    const l1 = leftShift(l0, 1), r1 = leftShift(r0, 1);
    const k1 = permute(l1 + r1, P8);
    steps.push({
      title: 'Generate Key K1 — Left Shift 1 (LS-1) + P8',
      html: `<p>L0 dan R0 masing-masing di-shift kiri 1 bit (LS-1).</p>
        ${ioRow([{ label: 'L1 = LS-1(L0)', val: l1 }, { label: 'R1 = LS-1(R0)', val: r1 }])}
        <p>Gabungan L1‖R1 dipermutasi dengan tabel <b>P8</b> = [${P8.join(',')}] menghasilkan <b>K1</b>.</p>
        ${ioRow([{ label: 'L1‖R1', val: miniBits(l1 + r1) }, { label: 'K1 (8 bit)', val: miniBits(k1), cls: 'key' }])}`
    });

    const l2 = leftShift(l1, 2), r2 = leftShift(r1, 2);
    const k2 = permute(l2 + r2, P8);
    steps.push({
      title: 'Generate Key K2 — Left Shift 2 (LS-2) + P8',
      html: `<p>L1 dan R1 masing-masing di-shift kiri 2 bit lagi (LS-2, total shift dari L0/R0 = 3).</p>
        ${ioRow([{ label: 'L2 = LS-2(L1)', val: l2 }, { label: 'R2 = LS-2(R1)', val: r2 }])}
        <p>Gabungan L2‖R2 dipermutasi dengan P8 menghasilkan <b>K2</b>.</p>
        ${ioRow([{ label: 'L2‖R2', val: miniBits(l2 + r2) }, { label: 'K2 (8 bit)', val: miniBits(k2), cls: 'key' }])}`
    });

    return { k1, k2 };
  }

  // ---------- fungsi fk ----------
  function fk(bits8, subkey, steps, roundLabel) {
    const [l, r] = splitHalf(bits8);
    const ep = permute(r, EP);
    const x = xorBits(ep, subkey);
    const [left4, right4] = splitHalf(x);
    const s0out = sboxLookup(S0, left4);
    const s1out = sboxLookup(S1, right4);
    const sOut = s0out + s1out;
    const p4 = permute(sOut, P4);
    const newL = xorBits(p4, l);

    steps.push({
      title: `${roundLabel} — fungsi fK`,
      html: `
        ${ioRow([{ label: 'L (4 bit)', val: miniBits(l) }, { label: 'R (4 bit)', val: miniBits(r) }])}
        <p>Ekspansi/Permutasi (E/P) terhadap R menggunakan tabel [${EP.join(',')}]:</p>
        ${ioRow([{ label: 'E/P(R) (8 bit)', val: miniBits(ep) }])}
        <p>XOR dengan subkey ronde:</p>
        ${ioRow([{ label: 'E/P(R)', val: miniBits(ep) }, { label: 'Subkey', val: miniBits(subkey), cls: 'key' }, { label: 'XOR', val: miniBits(x), cls: 'out' }])}
        <p>Hasil XOR dibagi dua nibble, masing-masing masuk S-Box S0 dan S1 (baris = bit1&amp;bit4, kolom = bit2&amp;bit3):</p>
        ${ioRow([
          { label: '4 bit kiri → S0', val: miniBits(left4) },
          { label: 'S0 output', val: miniBits(s0out), cls: 'out' },
          { label: '4 bit kanan → S1', val: miniBits(right4) },
          { label: 'S1 output', val: miniBits(s1out), cls: 'out' }
        ])}
        <p>Gabungan output S-Box (${sOut}) dipermutasi dengan <b>P4</b> = [${P4.join(',')}]:</p>
        ${ioRow([{ label: 'P4 output', val: miniBits(p4) }])}
        <p>XOR dengan L menghasilkan L baru; R tetap:</p>
        ${ioRow([{ label: 'P4 output', val: miniBits(p4) }, { label: 'L', val: miniBits(l) }, { label: 'L baru = P4 ⊕ L', val: miniBits(newL), cls: 'out' }])}
      `
    });
    return newL + r; // L'R (belum swap)
  }

  function run(ptBin8, keyBin10, mode, steps) {
    const { k1, k2 } = keySchedule(keyBin10, steps);
    const [ka, kb] = mode === 'enc' ? [k1, k2] : [k2, k1];

    const ip = permute(ptBin8, IP);
    steps.push({
      title: `Initial Permutation (IP)`,
      html: `<p>${mode === 'enc' ? 'Plaintext' : 'Ciphertext'} 8-bit dipermutasi dengan tabel <b>IP</b> = [${IP.join(',')}].</p>
        ${ioRow([{ label: 'Input', val: miniBits(ptBin8) }, { label: 'IP(Input)', val: miniBits(ip), cls: 'out' }])}`
    });

    const afterR1 = fk(ip, ka, steps, `Round Function 1 (menggunakan ${mode === 'enc' ? 'K1' : 'K2'})`);
    const [l1, r1] = splitHalf(afterR1);
    const swapped = r1 + l1;
    steps.push({
      title: 'Swap (SW)',
      html: `<p>Bagian kiri dan kanan hasil Round 1 ditukar sebelum masuk Round 2.</p>
        ${ioRow([{ label: 'Sebelum swap', val: miniBits(afterR1) }, { label: 'Setelah swap', val: miniBits(swapped), cls: 'out' }])}`
    });

    const afterR2 = fk(swapped, kb, steps, `Round Function 2 (menggunakan ${mode === 'enc' ? 'K2' : 'K1'})`);
    const finalOut = permute(afterR2, IPI);
    steps.push({
      title: 'Final Permutation (IP⁻¹)',
      html: `<p>Hasil Round 2 (tanpa swap) dipermutasi dengan tabel <b>IP⁻¹</b> = [${IPI.join(',')}] menjadi hasil akhir.</p>
        ${ioRow([{ label: 'Sebelum IP⁻¹', val: miniBits(afterR2) }, { label: `${mode === 'enc' ? 'Ciphertext' : 'Plaintext'} akhir`, val: miniBits(finalOut), cls: 'out' }])}`
    });

    return finalOut;
  }

  function encrypt(ptBin8, keyBin10) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Plaintext (8 bit)', val: miniBits(ptBin8) }, { label: 'Key (10 bit)', val: miniBits(keyBin10), cls: 'key' }]) });
    const result = run(ptBin8, keyBin10, 'enc', steps);
    return { result, steps };
  }

  function decrypt(ctBin8, keyBin10) {
    const steps = [];
    steps.push({ title: 'Diketahui', html: ioRow([{ label: 'Ciphertext (8 bit)', val: miniBits(ctBin8) }, { label: 'Key (10 bit)', val: miniBits(keyBin10), cls: 'key' }]) });
    const result = run(ctBin8, keyBin10, 'dec', steps);
    return { result, steps };
  }

  return { encrypt, decrypt };
})();
