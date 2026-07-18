"""
des.py — Implementasi referensi Data Encryption Standard (DES)
Digunakan untuk cross-check manual terhadap hasil aplikasi web.

Cara pakai (CLI):
    python des.py --mode enc --pt 0123456789ABCDEF --key 133457799BBCDFF1
    python des.py --mode dec --ct 85E813540F0AB405 --key 133457799BBCDFF1
    python des.py --mode enc --pt 0123456789ABCDEF --key 133457799BBCDFF1 -v
"""

import argparse

IP = [58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4, 62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8, 57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7]

IP_INV = [40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31, 38,6,46,14,54,22,62,30,
          37,5,45,13,53,21,61,29, 36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25]

PC1 = [57,49,41,33,25,17,9, 1,58,50,42,34,26,18, 10,2,59,51,43,35,27,
       19,11,3,60,52,44,36, 63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
       14,6,61,53,45,37,29, 21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5, 3,28,15,6,21,10, 23,19,12,4,26,8, 16,7,27,20,13,2,
       41,52,31,37,47,55, 30,40,51,45,33,48, 44,49,39,56,34,53, 46,42,50,36,29,32]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

E = [32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13, 12,13,14,15,16,17,
     16,17,18,19,20,21, 20,21,22,23,24,25, 24,25,26,27,28,29, 28,29,30,31,32,1]

P = [16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10,
     2,8,24,14, 32,27,3,9, 19,13,30,6, 22,11,4,25]

SBOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
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


def hex_to_bin(h, bits):
    return bin(int(h, 16))[2:].zfill(bits)[-bits:]


def bin_to_hex(b):
    return format(int(b, 2), 'X').zfill(len(b) // 4)


def sbox(i, bits6):
    row = int(bits6[0] + bits6[5], 2)
    col = int(bits6[1:5], 2)
    return format(SBOX[i][row][col], '04b')


def log(verbose, *args):
    if verbose:
        print(*args)


def key_schedule(key64, verbose=False):
    pc1 = permute(key64, PC1)
    c, d = split(pc1)
    log(verbose, f"[Key] PC1(key) = {bin_to_hex(pc1)} -> C0={c} D0={d}")
    subkeys = []
    for i in range(1, 17):
        c = left_shift(c, SHIFTS[i - 1])
        d = left_shift(d, SHIFTS[i - 1])
        k = permute(c + d, PC2)
        subkeys.append(k)
        log(verbose, f"[Key] Round {i:2d}: shift={SHIFTS[i-1]} C{i}={c} D{i}={d} K{i}={bin_to_hex(k)}")
    return subkeys


def feistel_round(l, r, k, round_num, verbose=False):
    er = permute(r, E)
    x = xor(er, k)
    s_out = ''
    for i in range(8):
        s_out += sbox(i, x[i * 6:i * 6 + 6])
    p_out = permute(s_out, P)
    new_r = xor(l, p_out)
    log(verbose, f"[Round {round_num:2d}] E(R)={bin_to_hex(er)} XOR K={bin_to_hex(k)} -> {bin_to_hex(x)}")
    log(verbose, f"[Round {round_num:2d}] SBox out={bin_to_hex(s_out)} P(...)={bin_to_hex(p_out)} R{round_num}={bin_to_hex(new_r)}")
    return r, new_r


def des_run(bits64, key64, mode, verbose=False):
    subkeys = key_schedule(key64, verbose)
    if mode == 'dec':
        subkeys = list(reversed(subkeys))

    ip = permute(bits64, IP)
    log(verbose, f"[IP] {bin_to_hex(ip)}")

    l, r = split(ip)
    for i in range(1, 17):
        l, r = feistel_round(l, r, subkeys[i - 1], i, verbose)

    combined = r + l  # R16 || L16 (tanpa swap di akhir ronde 16)
    final = permute(combined, IP_INV)
    log(verbose, f"[Final] R16||L16={bin_to_hex(combined)} -> IP-1 -> {bin_to_hex(final)}")
    return final


def des_encrypt(plaintext_hex, key_hex, verbose=False):
    pt = hex_to_bin(plaintext_hex, 64)
    key = hex_to_bin(key_hex, 64)
    return bin_to_hex(des_run(pt, key, 'enc', verbose))


def des_decrypt(ciphertext_hex, key_hex, verbose=False):
    ct = hex_to_bin(ciphertext_hex, 64)
    key = hex_to_bin(key_hex, 64)
    return bin_to_hex(des_run(ct, key, 'dec', verbose))


def main():
    ap = argparse.ArgumentParser(description="Simulasi DES (CLI reference implementation)")
    ap.add_argument('--mode', choices=['enc', 'dec'], required=True)
    ap.add_argument('--pt', help='plaintext 64-bit hex (mode enc)')
    ap.add_argument('--ct', help='ciphertext 64-bit hex (mode dec)')
    ap.add_argument('--key', required=True, help='key 64-bit hex')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.mode == 'enc':
        if not args.pt:
            ap.error('--pt wajib diisi untuk mode enc')
        print(f"Ciphertext: {des_encrypt(args.pt, args.key, args.verbose)}")
    else:
        if not args.ct:
            ap.error('--ct wajib diisi untuk mode dec')
        print(f"Plaintext : {des_decrypt(args.ct, args.key, args.verbose)}")


if __name__ == '__main__':
    main()
