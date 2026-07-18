"""
saes.py — Implementasi referensi Simplified AES (S-AES)
Digunakan untuk cross-check manual terhadap hasil aplikasi web.

Cara pakai (CLI):
    python saes.py --mode enc --pt D728 --key 4AF5
    python saes.py --mode dec --ct 24EC --key 4AF5
"""

import argparse

SBOX = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7]
INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON1, RCON2 = 0x80, 0x30


def gmul(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a = (a << 1) & 0xF
        if hi:
            a ^= 0x3
        b >>= 1
    return p & 0xF


def nibbles(byte):
    return (byte >> 4) & 0xF, byte & 0xF


def to_byte(hi, lo):
    return ((hi & 0xF) << 4) | (lo & 0xF)


def sub_word(byte):
    h, l = nibbles(byte)
    return to_byte(SBOX[h], SBOX[l])


def rot_word(byte):
    h, l = nibbles(byte)
    return to_byte(l, h)


def bytes_to_state(b0, b1):
    s0, s1 = nibbles(b0)
    s2, s3 = nibbles(b1)
    return [[s0, s2], [s1, s3]]


def state_to_hex(s):
    return f"{s[0][0]:X}{s[1][0]:X}{s[0][1]:X}{s[1][1]:X}"


def log(verbose, *args):
    if verbose:
        print(*args)


def key_expansion(key_hex, verbose=False):
    w0 = int(key_hex[0:2], 16)
    w1 = int(key_hex[2:4], 16)

    def g(w, rcon):
        return sub_word(rot_word(w)) ^ rcon

    gw1 = g(w1, RCON1)
    w2 = w0 ^ gw1
    w3 = w2 ^ w1
    log(verbose, f"[KeyExp] w0={w0:02X} w1={w1:02X} g(w1)={gw1:02X} w2={w2:02X} w3={w3:02X}")

    gw3 = g(w3, RCON2)
    w4 = w2 ^ gw3
    w5 = w4 ^ w3
    log(verbose, f"[KeyExp] g(w3)={gw3:02X} w4={w4:02X} w5={w5:02X}")

    return bytes_to_state(w0, w1), bytes_to_state(w2, w3), bytes_to_state(w4, w5)


def sub_nib(s, inv=False):
    box = INV_SBOX if inv else SBOX
    return [[box[s[0][0]], box[s[0][1]]], [box[s[1][0]], box[s[1][1]]]]


def shift_rows(s):
    return [[s[0][0], s[0][1]], [s[1][1], s[1][0]]]


def mix_columns(s, inv=False):
    M = [[9, 2], [2, 9]] if inv else [[1, 4], [4, 1]]
    out = [[0, 0], [0, 0]]
    for c in range(2):
        col = [s[0][c], s[1][c]]
        out[0][c] = gmul(M[0][0], col[0]) ^ gmul(M[0][1], col[1])
        out[1][c] = gmul(M[1][0], col[0]) ^ gmul(M[1][1], col[1])
    return out


def add_round_key(s, k):
    return [[s[0][0] ^ k[0][0], s[0][1] ^ k[0][1]], [s[1][0] ^ k[1][0], s[1][1] ^ k[1][1]]]


def saes_run(input_hex, key_hex, mode, verbose=False):
    b0, b1 = int(input_hex[0:2], 16), int(input_hex[2:4], 16)
    state = bytes_to_state(b0, b1)
    k0, k1, k2 = key_expansion(key_hex, verbose)

    init_key = k0 if mode == 'enc' else k2
    state = add_round_key(state, init_key)
    log(verbose, f"[Initial] AddRoundKey -> {state_to_hex(state)}")

    if mode == 'enc':
        state = sub_nib(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, k1)
        log(verbose, f"[Round1] -> {state_to_hex(state)}")

        state = sub_nib(state)
        state = shift_rows(state)
        state = add_round_key(state, k2)
        log(verbose, f"[Round2] -> {state_to_hex(state)}")
    else:
        state = shift_rows(state)
        state = sub_nib(state, inv=True)
        state = add_round_key(state, k1)
        state = mix_columns(state, inv=True)
        log(verbose, f"[Round1 dec] -> {state_to_hex(state)}")

        state = shift_rows(state)
        state = sub_nib(state, inv=True)
        state = add_round_key(state, k0)
        log(verbose, f"[Round2 dec] -> {state_to_hex(state)}")

    return state_to_hex(state)


def saes_encrypt(pt_hex, key_hex, verbose=False):
    return saes_run(pt_hex, key_hex, 'enc', verbose)


def saes_decrypt(ct_hex, key_hex, verbose=False):
    return saes_run(ct_hex, key_hex, 'dec', verbose)


def main():
    ap = argparse.ArgumentParser(description="Simulasi S-AES (CLI reference implementation)")
    ap.add_argument('--mode', choices=['enc', 'dec'], required=True)
    ap.add_argument('--pt', help='plaintext 16-bit hex (mode enc)')
    ap.add_argument('--ct', help='ciphertext 16-bit hex (mode dec)')
    ap.add_argument('--key', required=True, help='key 16-bit hex')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.mode == 'enc':
        if not args.pt:
            ap.error('--pt wajib diisi untuk mode enc')
        print(f"Ciphertext: {saes_encrypt(args.pt, args.key, args.verbose)}")
    else:
        if not args.ct:
            ap.error('--ct wajib diisi untuk mode dec')
        print(f"Plaintext : {saes_decrypt(args.ct, args.key, args.verbose)}")


if __name__ == '__main__':
    main()
