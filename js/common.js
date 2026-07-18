/* =========================================================
   common.js — helper bersama untuk seluruh modul simulasi
   Berisi: konversi bit/hex, permutasi, XOR, validasi input,
   render step-by-step (accordion), render bit/matrix, dan
   wiring UI generik (mode toggle, submit, reset, expand-all).
   ========================================================= */

const $  = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

/* ---------------- konversi dasar ---------------- */

// hex string -> string biner dengan panjang tetap (bits = total bit yang diinginkan)
function hexToBin(hex, bits) {
  hex = hex.trim().replace(/^0x/i, '');
  let bin = '';
  for (const c of hex) bin += parseInt(c, 16).toString(2).padStart(4, '0');
  return bin.padStart(bits, '0').slice(-bits);
}

// string biner -> hex (panjang dibulatkan ke atas ke kelipatan 4)
function binToHex(bin) {
  let padded = bin.padStart(Math.ceil(bin.length / 4) * 4, '0');
  let hex = '';
  for (let i = 0; i < padded.length; i += 4) {
    hex += parseInt(padded.slice(i, i + 4), 2).toString(16);
  }
  return hex.toUpperCase();
}

function isBinaryStr(s) { return /^[01]+$/.test(s); }
function isHexStr(s) { return /^[0-9a-fA-F]+$/.test(s.replace(/^0x/i, '')); }

// Menerima input yang boleh berupa biner ATAU hex, mengembalikan string biner sepanjang `bits`
function anyToBin(str, bits) {
  str = str.trim();
  if (isBinaryStr(str) && str.length === bits) return str;
  if (isHexStr(str)) return hexToBin(str, bits);
  if (isBinaryStr(str)) return str.padStart(bits, '0').slice(-bits);
  return null;
}

/* ---------------- operasi bit ---------------- */

// permute: tabel berisi indeks 1-based posisi bit sumber
function permute(bits, table) {
  return table.map(i => bits[i - 1]).join('');
}

function xorBits(a, b) {
  let out = '';
  for (let i = 0; i < a.length; i++) out += (a[i] === b[i]) ? '0' : '1';
  return out;
}

function leftShift(bits, n) {
  n = n % bits.length;
  return bits.slice(n) + bits.slice(0, n);
}

function splitHalf(bits) {
  const h = bits.length / 2;
  return [bits.slice(0, h), bits.slice(h)];
}

/* ---------------- validasi ---------------- */

function validateField(inputEl, errEl, bits, label) {
  const v = inputEl.value.trim();
  let bin = anyToBin(v, bits);
  if (!v) {
    showErr(inputEl, errEl, `${label} tidak boleh kosong.`);
    return null;
  }
  if (!bin) {
    showErr(inputEl, errEl, `${label} harus biner (0/1) atau hex valid sepanjang ${bits} bit.`);
    return null;
  }
  clearErr(inputEl, errEl);
  return bin;
}

function showErr(inputEl, errEl, msg) {
  inputEl.classList.add('err');
  errEl.textContent = msg;
  errEl.classList.add('show');
}
function clearErr(inputEl, errEl) {
  inputEl.classList.remove('err');
  errEl.classList.remove('show');
}

/* ---------------- render bit / byte / matrix ---------------- */

function renderBitGrid(container, bits) {
  container.innerHTML = '';
  container.className = 'bitgrid';
  for (const b of bits) {
    const d = document.createElement('div');
    d.className = 'bit';
    d.textContent = b;
    container.appendChild(d);
  }
}

function renderByteGrid(container, bytesHexArr) {
  container.innerHTML = '';
  container.className = 'bytegrid';
  for (const b of bytesHexArr) {
    const d = document.createElement('div');
    d.className = 'byte';
    d.textContent = b;
    container.appendChild(d);
  }
}

function miniBits(bits) {
  return `<div class="mini-bits">${[...bits].map(b => `<span>${b}</span>`).join('')}</div>`;
}

function ioRow(items) {
  // items: [{label, val, cls}]
  return `<div class="row-io">${items.map(it => `
    <div class="io-block">
      <div class="io-label">${it.label}</div>
      <div class="io-val ${it.cls || ''}">${it.val}</div>
    </div>`).join('')}</div>`;
}

function htmlTable(headers, rows) {
  return `<table><thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

// matrix generik state 4x4 (AES, byte hex) atau 2x2 (S-AES, nibble hex)
function matrixHtml(cells, rows, cols, opts = {}) {
  // cells: array (row-major kalau opts.rowMajor true, default column-major seperti standar AES state)
  const cls = opts.cls || '';
  let html = `<div class="matrix" style="grid-template-columns:repeat(${cols},auto);grid-template-rows:repeat(${rows},auto);">`;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const idx = opts.rowMajor ? r * cols + c : c * rows + r;
      html += `<div class="cell ${cls}">${cells[idx]}</div>`;
    }
  }
  html += '</div>';
  return html;
}

/* ---------------- render step accordion ---------------- */

function renderSteps(container, steps) {
  container.innerHTML = '';
  steps.forEach((s, i) => {
    const wrap = document.createElement('div');
    wrap.className = 'step';
    wrap.innerHTML = `
      <div class="step-head">
        <div class="step-idx">${String(i + 1).padStart(2, '0')}</div>
        <div class="step-title">${s.title}</div>
        <div class="step-chevron">&#9656;</div>
      </div>
      <div class="step-body">${s.html}</div>`;
    wrap.querySelector('.step-head').addEventListener('click', () => {
      wrap.classList.toggle('open');
    });
    container.appendChild(wrap);
  });
}

function setAllSteps(container, open) {
  $$('.step', container).forEach(s => s.classList.toggle('open', open));
}

/* ---------------- wiring UI generik modul ---------------- */

function initModePage() {
  const modeButtons = $$('.mode-toggle button');
  let mode = 'enc';
  modeButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      modeButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      mode = btn.dataset.mode;
      document.dispatchEvent(new CustomEvent('modechange', { detail: mode }));
    });
  });

  const toggleBtn = $('#toggleSolution');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const wrap = $('#stepsWrap');
      const showing = wrap.classList.toggle('show');
      toggleBtn.textContent = showing ? 'Sembunyikan Solusi Penyelesaian' : 'Tampilkan Solusi Penyelesaian';
    });
  }

  const expandAll = $('#expandAll');
  const collapseAll = $('#collapseAll');
  if (expandAll) expandAll.addEventListener('click', () => setAllSteps($('#stepsWrap'), true));
  if (collapseAll) collapseAll.addEventListener('click', () => setAllSteps($('#stepsWrap'), false));

  const copyBtn = $('#copyResult');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const val = $('#resultValue').textContent;
      navigator.clipboard.writeText(val).then(() => {
        const old = copyBtn.textContent;
        copyBtn.textContent = 'Tersalin!';
        setTimeout(() => copyBtn.textContent = old, 1200);
      });
    });
  }

  return { getMode: () => mode };
}

function resetForm(formSelector) {
  $$(`${formSelector} input[type=text]`).forEach(i => { i.value = ''; i.classList.remove('err'); });
  $$(`${formSelector} .errmsg`).forEach(e => e.classList.remove('show'));
  const result = $('#resultBox');
  if (result) result.classList.remove('show');
  const steps = $('#stepsWrap');
  if (steps) { steps.classList.remove('show'); }
  const toggleBtn = $('#toggleSolution');
  if (toggleBtn) toggleBtn.textContent = 'Tampilkan Solusi Penyelesaian';
}
