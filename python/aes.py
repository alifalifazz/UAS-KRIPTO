"""
aes.py — Implementasi referensi AES-128
Digunakan untuk cross-check manual terhadap hasil aplikasi web.

Cara pakai (CLI):
    python aes.py --mode enc --pt 00112233445566778899AABBCCDDEEFF --key 000102030405060708090A0B0C0D0E0F
    python aes.py --mode dec --ct 69C4E0D86A7B0430D8CDB78070B4C55A --key 000102030405060708090A0B0C0D0E0F
"""

import argparse

SBOX = [
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def hex_to_bytes(h):
    return [int(h[i:i + 2], 16) for i in range(0, len(h), 2)]


def bytes_to_hex(b):
    return ''.join(f'{x:02X}' for x in b)


def bytes_to_state(b):
    return [[b[c * 4 + r] for c in range(4)] for r in range(4)]


def state_to_bytes(s):
    return [s[r][c] for c in range(4) for r in range(4)]


def log(verbose, *args):
    if verbose:
        print(*args)


def key_expansion(key_bytes, verbose=False):
    w = [key_bytes[i * 4:i * 4 + 4] for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            rot = temp[1:] + temp[:1]
            sub = [SBOX[b] for b in rot]
            rcon = [RCON[i // 4 - 1], 0, 0, 0]
            temp = [sub[k] ^ rcon[k] for k in range(4)]
        wi = [w[i - 4][k] ^ temp[k] for k in range(4)]
        w.append(wi)
        log(verbose, f"[KeyExp] w{i} = {bytes_to_hex(wi)}")
    round_keys = []
    for r in range(11):
        flat = [b for word in w[r * 4:r * 4 + 4] for b in word]
        round_keys.append(bytes_to_state(flat))
    return round_keys


def sub_bytes(s, inv=False):
    box = INV_SBOX if inv else SBOX
    return [[box[s[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(s, inv=False):
    out = [[0] * 4 for _ in range(4)]
    for r in range(4):
        shift = (4 - r) % 4 if inv else r
        for c in range(4):
            out[r][c] = s[r][(c + shift) % 4]
    return out


def mix_columns(s, inv=False):
    M = [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]] if inv else [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        for r in range(4):
            out[r][c] = 0
            for k in range(4):
                out[r][c] ^= gmul(M[r][k], col[k])
    return out


def add_round_key(s, rk):
    return [[s[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


def aes_run(input_hex, key_hex, mode, verbose=False):
    state = bytes_to_state(hex_to_bytes(input_hex))
    round_keys = key_expansion(hex_to_bytes(key_hex), verbose)
    rks = round_keys if mode == 'enc' else list(reversed(round_keys))

    state = add_round_key(state, rks[0])
    log(verbose, f"[Initial] AddRoundKey(RK0) -> {bytes_to_hex(state_to_bytes(state))}")

    if mode == 'enc':
        for rnd in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, rks[rnd])
            log(verbose, f"[Round {rnd}] -> {bytes_to_hex(state_to_bytes(state))}")
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, rks[10])
        log(verbose, f"[Round 10 - final] -> {bytes_to_hex(state_to_bytes(state))}")
    else:
        for rnd in range(1, 10):
            state = shift_rows(state, inv=True)
            state = sub_bytes(state, inv=True)
            state = add_round_key(state, rks[rnd])
            state = mix_columns(state, inv=True)
            log(verbose, f"[Round {rnd} dec] -> {bytes_to_hex(state_to_bytes(state))}")
        state = shift_rows(state, inv=True)
        state = sub_bytes(state, inv=True)
        state = add_round_key(state, rks[10])
        log(verbose, f"[Round 10 dec - final] -> {bytes_to_hex(state_to_bytes(state))}")

    return bytes_to_hex(state_to_bytes(state))


def aes_encrypt(pt_hex, key_hex, verbose=False):
    return aes_run(pt_hex, key_hex, 'enc', verbose)


def aes_decrypt(ct_hex, key_hex, verbose=False):
    return aes_run(ct_hex, key_hex, 'dec', verbose)


def main():
    ap = argparse.ArgumentParser(description="Simulasi AES-128 (CLI reference implementation)")
    ap.add_argument('--mode', choices=['enc', 'dec'], required=True)
    ap.add_argument('--pt', help='plaintext 128-bit hex (mode enc)')
    ap.add_argument('--ct', help='ciphertext 128-bit hex (mode dec)')
    ap.add_argument('--key', required=True, help='key 128-bit hex')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.mode == 'enc':
        if not args.pt:
            ap.error('--pt wajib diisi untuk mode enc')
        print(f"Ciphertext: {aes_encrypt(args.pt, args.key, args.verbose)}")
    else:
        if not args.ct:
            ap.error('--ct wajib diisi untuk mode dec')
        print(f"Plaintext : {aes_decrypt(args.ct, args.key, args.verbose)}")


if __name__ == '__main__':
    main()
