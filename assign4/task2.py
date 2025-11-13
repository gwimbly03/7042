import math
import random
import os

def bbs_init(p, q, seed=None):
    assert p % 4 == 3 and q % 4 == 3
    n = p * q
    if seed is None:
        while True:
            seed = random.randrange(2, n - 1)
            if math.gcd(seed, n) == 1:
                break
    x = pow(seed, 2, n)
    return n, x

def bbs_next_bit(x, n):
    x = pow(x, 2, n)
    return x & 1, x

def bbs_bits(n, x, k):
    bits = []
    for _ in range(k):
        bit, x = bbs_next_bit(x, n)
        bits.append(bit)
    return bits, x

def bits_to_bytes(bits):
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
            else:
                byte <<= 1
        b.append(byte)
    return bytes(b)

def generate_aes_key_bbs(bits=256):
    def gen_3mod4(bits):
        while True:
            r = random.getrandbits(bits) | 1 | (1 << (bits - 1))
            if r % 4 == 3:
                return r
    p = gen_3mod4(bits // 2)
    q = gen_3mod4(bits // 2)
    n, x = bbs_init(p, q)
    key_bits, _ = bbs_bits(n, x, bits)
    key_bytes = bits_to_bytes(key_bits)
    return key_bytes

Nb = 4
Nk = 8
Nr = 14

sbox = [
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
]

inv_sbox = [0]*256
for i in range(256):
    inv_sbox[sbox[i]] = i

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]
    return state

def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]
    return state

def inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]
    return state

def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def mix_columns(state):
    for i in range(4):
        col = [state[r][i] for r in range(4)]
        col = mix_single_column(col)
        for r in range(4):
            state[r][i] = col[r]
    return state

def inv_mix_columns(state):
    for i in range(4):
        s0 = state[0][i]
        s1 = state[1][i]
        s2 = state[2][i]
        s3 = state[3][i]
        state[0][i] = mul(0x0e,s0)^mul(0x0b,s1)^mul(0x0d,s2)^mul(0x09,s3)
        state[1][i] = mul(0x09,s0)^mul(0x0e,s1)^mul(0x0b,s2)^mul(0x0d,s3)
        state[2][i] = mul(0x0d,s0)^mul(0x09,s1)^mul(0x0e,s2)^mul(0x0b,s3)
        state[3][i] = mul(0x0b,s0)^mul(0x0d,s1)^mul(0x09,s2)^mul(0x0e,s3)
    return state

def mul(a,b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1b
        b >>= 1
    return p

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def pad(plaintext):
    pad_len = 16 - (len(plaintext) % 16)
    return plaintext + bytes([pad_len]*pad_len)

def unpad(padded):
    pad_len = padded[-1]
    return padded[:-pad_len]

def bytes2matrix(b):
    return [[b[4*c+r] for c in range(4)] for r in range(4)]

def matrix2bytes(m):
    return bytes(m[r][c] for c in range(4) for r in range(4))

def aes_encrypt_block(block, round_keys):
    state = bytes2matrix(block)
    state = add_round_key(state, round_keys[0])
    for r in range(1, Nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])
    return matrix2bytes(state)

def aes_decrypt_block(block, round_keys):
    state = bytes2matrix(block)
    state = add_round_key(state, round_keys[Nr])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for r in range(Nr-1, 0, -1):
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return matrix2bytes(state)

Rcon = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000,
    0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1B000000, 0x36000000, 0x6C000000,
    0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000
]

def sub_word(word):
    return ((sbox[(word >> 24) & 0xFF] << 24) |
            (sbox[(word >> 16) & 0xFF] << 16) |
            (sbox[(word >> 8) & 0xFF] << 8) |
            (sbox[word & 0xFF]))

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def aes_key_schedule(key_bytes):
    assert len(key_bytes) == 32
    Nk = 8
    Nr = 14
    Nb = 4
    w = [0] * (Nb * (Nr + 1))
    for i in range(Nk):
        w[i] = (key_bytes[4*i] << 24) | (key_bytes[4*i+1] << 16) | (key_bytes[4*i+2] << 8) | key_bytes[4*i+3]
    for i in range(Nk, Nb * (Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ Rcon[i//Nk]
        elif i % Nk == 4:
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    round_keys = []
    for r in range(Nr+1):
        mat = [[0]*4 for _ in range(4)]
        for c in range(4):
            word = w[r*4 + c]
            mat[0][c] = (word >> 24) & 0xFF
            mat[1][c] = (word >> 16) & 0xFF
            mat[2][c] = (word >> 8) & 0xFF
            mat[3][c] = word & 0xFF
        round_keys.append(mat)
    return round_keys

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_cbc_encrypt(plaintext, key, iv, round_keys):
    plaintext = pad(plaintext)  # Add padding
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        block = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted_block = aes_encrypt_block(block, round_keys)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv, round_keys):
    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(block, round_keys)
        decrypted_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += decrypted_block
        prev_block = block
    return unpad(plaintext)

def main():
    key = generate_aes_key_bbs(256)
    print("AES-256 Key:", key.hex())
    
    iv = os.urandom(16)
    print("IV:", iv.hex())
    
    plaintext = input("Enter the message to encrypt: ")
    plaintext = plaintext.encode('utf-8')
    print("Plaintext:", plaintext)
    
    round_keys = aes_key_schedule(key)
    
    ciphertext = aes_cbc_encrypt(plaintext, key, iv, round_keys)
    print("Ciphertext (hex):", ciphertext.hex())

    decrypted = aes_cbc_decrypt(ciphertext, key, iv, round_keys)
    print("Decrypted:", decrypted.decode('utf-8'))

if __name__ == "__main__":
    main()
