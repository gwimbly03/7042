import math
import random
import os

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

Rcon = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, #im only using the first 10
0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]  


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
        b.append(byte)
    return bytes(b)

def generate_aes_key_bbs(bits=256):
    def gen_3mod4(bitlen):
        while True:
            r = random.getrandbits(bitlen) | 1
            r |= (1 << (bitlen - 1))  
            if r % 4 == 3 and r > 1000:
                return r
    p = gen_3mod4(bits // 2 + 8)
    q = gen_3mod4(bits // 2 + 8)
    while p == q:
        q = gen_3mod4(bits // 2 + 8)
    n, x = bbs_init(p, q)
    key_bits, _ = bbs_bits(n, x, bits)
    return bits_to_bytes(key_bits[:bits])  


inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i


def mul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11b
        b >>= 1
    return p & 0xFF

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
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    return state

def mix_columns(state):
    for i in range(4):
        a = [state[r][i] for r in range(4)]
        state[0][i] = mul(2, a[0]) ^ mul(3, a[1]) ^ a[2] ^ a[3]
        state[1][i] = a[0] ^ mul(2, a[1]) ^ mul(3, a[2]) ^ a[3]
        state[2][i] = a[0] ^ a[1] ^ mul(2, a[2]) ^ mul(3, a[3])
        state[3][i] = mul(3, a[0]) ^ a[1] ^ a[2] ^ mul(2, a[3])
    return state

def inv_mix_columns(state):
    for i in range(4):
        a = [state[r][i] for r in range(4)]
        state[0][i] = mul(0x0e, a[0]) ^ mul(0x0b, a[1]) ^ mul(0x0d, a[2]) ^ mul(0x09, a[3])
        state[1][i] = mul(0x09, a[0]) ^ mul(0x0e, a[1]) ^ mul(0x0b, a[2]) ^ mul(0x0d, a[3])
        state[2][i] = mul(0x0d, a[0]) ^ mul(0x09, a[1]) ^ mul(0x0e, a[2]) ^ mul(0x0b, a[3])
        state[3][i] = mul(0x0b, a[0]) ^ mul(0x0d, a[1]) ^ mul(0x09, a[2]) ^ mul(0x0e, a[3])
    return state

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def key_expansion(key):
    w = [0] * (4 * (Nr + 1))
    for i in range(Nk):
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
    
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ Rcon[i//Nk - 1]
        elif Nk > 6 and i % Nk == 4:  
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    
    round_keys = []
    for i in range(Nr + 1):
        rk = [[0]*4 for _ in range(4)]
        for j in range(4):
            word = w[i*4 + j]
            rk[0][j] = (word >> 24) & 0xFF
            rk[1][j] = (word >> 16) & 0xFF
            rk[2][j] = (word >> 8)  & 0xFF
            rk[3][j] = word & 0xFF
        round_keys.append(rk)
    return round_keys

def sub_word(w):
    return (sbox[(w >> 24) & 0xFF] << 24) | \
           (sbox[(w >> 16) & 0xFF] << 16) | \
           (sbox[(w >> 8)  & 0xFF] << 8)  | \
           sbox[w & 0xFF]

def rot_word(w):
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)

def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    return bytes(matrix[r][c] for r in range(4) for c in range(4))

def encrypt_block(plaintext, round_keys):
    state = bytes2matrix(plaintext)
    add_round_key(state, round_keys[0])
    
    for round in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round])
    
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[Nr])
    
    return matrix2bytes(state)

def decrypt_block(ciphertext, round_keys):
    state = bytes2matrix(ciphertext)
    
    add_round_key(state, round_keys[Nr])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    
    for round in range(Nr-1, 0, -1):
        add_round_key(state, round_keys[round])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    
    add_round_key(state, round_keys[0])
    return matrix2bytes(state)

def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    return plaintext + bytes([padding_len] * padding_len)

def unpad(padded):
    padding_len = padded[-1]
    if padding_len < 1 or padding_len > 16:
        return padded
    return padded[:-padding_len]

def aes_cbc_encrypt(plaintext_bytes, key, iv):
    plaintext_bytes = pad(plaintext_bytes)
    round_keys = key_expansion(key)
    ciphertext = b""
    prev = iv
    
    for i in range(0, len(plaintext_bytes), 16):
        block = plaintext_bytes[i:i+16]
        block = bytes(a ^ b for a, b in zip(block, prev))
        encrypted = encrypt_block(block, round_keys)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    round_keys = key_expansion(key)
    plaintext = b""
    prev = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = decrypt_block(block, round_keys)
        decrypted = bytes(a ^ b for a, b in zip(decrypted, prev))
        plaintext += decrypted
        prev = block
    return unpad(plaintext)

def main():
    print("AES256 CBC with BBS Key Gen\n")
    
    key = generate_aes_key_bbs(256)
    print(f"Generated 256 bit AES Key (BBS): {key.hex()}\n")
    
    iv = os.urandom(16)
    print(f"Random IV: {iv.hex()}\n")
    
    message = input("Enter your secret message: ")
    plaintext = message.encode('utf-8')
    print(f"\nPlaintext: {message}\n")
    
    ciphertext = aes_cbc_encrypt(plaintext, key, iv)
    print(f"Ciphertext (hex): {ciphertext.hex()}\n")
    
    decrypted = aes_cbc_decrypt(ciphertext, key, iv)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    
    if decrypted == plaintext:
        print("\nEncrypt and decrypt success")
    else:
        print("\nFailed")

if __name__ == "__main__":
  main() 
