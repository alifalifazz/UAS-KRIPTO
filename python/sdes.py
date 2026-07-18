"""
sdes.py — Implementasi referensi Simplified DES (S-DES)
Digunakan untuk cross-check manual terhadap hasil aplikasi web.

Cara pakai (CLI):
    python sdes.py --mode enc --pt 10111101 --key 1010000010
    python sdes.py --mode dec --ct 00010001 --key 1010000010
    python sdes.py --mode enc --pt 10111101 --key 1010000010 -v   # tampilkan langkah

Bisa juga diimport sebagai modul:
    from sdes import sdes_encrypt, sdes_decrypt
"""

import argparse

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2],
]
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3],
]


def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)


def xor(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))


def left_shift(bits, n):
    n %= len(bits)
    return bits[n:] + bits[:n]


def split(bits):
    h = len(bits) // 2
    return bits[:h], bits[h:]


def sbox_lookup(box, bits4):
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1] + bits4[2], 2)
    return format(box[row][col], '02b')


def log(verbose, *args):
    if verbose:
        print(*args)


def key_schedule(key10, verbose=False):
    p10 = permute(key10, P10)
    l0, r0 = split(p10)
    log(verbose, f"[Key] P10({key10}) = {p10}  ->  L0={l0} R0={r0}")

    l1, r1 = left_shift(l0, 1), left_shift(r0, 1)
    k1 = permute(l1 + r1, P8)
    log(verbose, f"[Key] LS-1: L1={l1} R1={r1}  ->  P8(L1R1) = K1 = {k1}")

    l2, r2 = left_shift(l1, 2), left_shift(r1, 2)
    k2 = permute(l2 + r2, P8)
    log(verbose, f"[Key] LS-2: L2={l2} R2={r2}  ->  P8(L2R2) = K2 = {k2}")

    return k1, k2


def fk(bits8, subkey, verbose=False, label=""):
    l, r = split(bits8)
    ep = permute(r, EP)
    x = xor(ep, subkey)
    left4, right4 = split(x)
    s0out = sbox_lookup(S0, left4)
    s1out = sbox_lookup(S1, right4)
    s_out = s0out + s1out
    p4 = permute(s_out, P4)
    new_l = xor(p4, l)
    log(verbose, f"[{label}] L={l} R={r} | E/P(R)={ep} XOR K={subkey} -> {x}")
    log(verbose, f"[{label}] S0({left4})={s0out} S1({right4})={s1out} | P4({s_out})={p4} | L'=P4^L={new_l}")
    return new_l + r


def sdes_run(bits8, key10, mode, verbose=False):
    k1, k2 = key_schedule(key10, verbose)
    ka, kb = (k1, k2) if mode == 'enc' else (k2, k1)

    ip = permute(bits8, IP)
    log(verbose, f"[IP] IP({bits8}) = {ip}")

    after_r1 = fk(ip, ka, verbose, "Round1")
    l1, r1 = split(after_r1)
    swapped = r1 + l1
    log(verbose, f"[SWAP] {after_r1} -> {swapped}")

    after_r2 = fk(swapped, kb, verbose, "Round2")
    final = permute(after_r2, IP_INV)
    log(verbose, f"[IP-1] IP-1({after_r2}) = {final}")
    return final


def sdes_encrypt(plaintext8, key10, verbose=False):
    return sdes_run(plaintext8, key10, 'enc', verbose)


def sdes_decrypt(ciphertext8, key10, verbose=False):
    return sdes_run(ciphertext8, key10, 'dec', verbose)


def main():
    ap = argparse.ArgumentParser(description="Simulasi S-DES (CLI reference implementation)")
    ap.add_argument('--mode', choices=['enc', 'dec'], required=True)
    ap.add_argument('--pt', help='plaintext 8-bit biner (mode enc)')
    ap.add_argument('--ct', help='ciphertext 8-bit biner (mode dec)')
    ap.add_argument('--key', required=True, help='key 10-bit biner')
    ap.add_argument('-v', '--verbose', action='store_true', help='tampilkan langkah perhitungan')
    args = ap.parse_args()

    if args.mode == 'enc':
        if not args.pt:
            ap.error('--pt wajib diisi untuk mode enc')
        result = sdes_encrypt(args.pt, args.key, args.verbose)
        print(f"Ciphertext: {result}")
    else:
        if not args.ct:
            ap.error('--ct wajib diisi untuk mode dec')
        result = sdes_decrypt(args.ct, args.key, args.verbose)
        print(f"Plaintext : {result}")


if __name__ == '__main__':
    main()
