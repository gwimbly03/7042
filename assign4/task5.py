import math
import random
import os
import secrets
from time import time

class Task2:

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

    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i

    Rcon = [
        0x01000000,0x02000000,0x04000000,0x08000000,
        0x10000000,0x20000000,0x40000000,0x80000000,
        0x1B000000,0x36000000
    ]


    @staticmethod
    def mul(a, b):
        """Multiply two bytes in GF(2^8)."""
        p = 0
        while b:
            if b & 1:
                p ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11b
            b >>= 1
        return p & 0xFF

    @classmethod
    def sub_word(cls, w):
        """Apply S-box substitution to a 4-byte word."""
        return (
            cls.sbox[(w >> 24) & 0xFF] << 24 |
            cls.sbox[(w >> 16) & 0xFF] << 16 |
            cls.sbox[(w >> 8)  & 0xFF] << 8  |
            cls.sbox[w & 0xFF]
        )

    @staticmethod
    def rot_word(w):
        """Rotate a 4-byte word left by 1 byte."""
        return ((w << 8) & 0xFFFFFFFF) | (w >> 24)

    @classmethod
    def key_expansion(cls, key_bytes):
        """Expand AES key into round keys."""
        w = [0] * (4 * (cls.Nr + 1))

        for i in range(cls.Nk):
            w[i] = (
                (key_bytes[4*i] << 24) |
                (key_bytes[4*i+1] << 16) |
                (key_bytes[4*i+2] << 8) |
                key_bytes[4*i+3]
            )

        for i in range(cls.Nk, 4*(cls.Nr+1)):
            temp = w[i-1]
            if i % cls.Nk == 0:
                temp = cls.sub_word(cls.rot_word(temp)) ^ cls.Rcon[i//cls.Nk - 1]
            elif cls.Nk > 6 and i % cls.Nk == 4:
                temp = cls.sub_word(temp)
            w[i] = w[i - cls.Nk] ^ temp

        round_keys = []
        for i in range(cls.Nr + 1):
            rk = [[0]*4 for _ in range(4)]
            for j in range(4):
                word = w[i*4 + j]
                rk[0][j] = (word >> 24) & 0xFF
                rk[1][j] = (word >> 16) & 0xFF
                rk[2][j] = (word >> 8)  & 0xFF
                rk[3][j] = word & 0xFF
            round_keys.append(rk)
        return round_keys

    @staticmethod
    def bytes2matrix(text):
        """Convert 16-byte array to 4x4 matrix."""
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    @staticmethod
    def matrix2bytes(matrix):
        """Convert 4x4 matrix to 16-byte array."""
        return bytes(matrix[r][c] for r in range(4) for c in range(4))

    @classmethod
    def encrypt_block(cls, plaintext, round_keys):
        """Encrypt a single 16-byte block."""
        state = cls.bytes2matrix(plaintext)
        cls.add_round_key(state, round_keys[0])

        for rnd in range(1, cls.Nr):
            cls.sub_bytes(state)
            cls.shift_rows(state)
            cls.mix_columns(state)
            cls.add_round_key(state, round_keys[rnd])

        cls.sub_bytes(state)
        cls.shift_rows(state)
        cls.add_round_key(state, round_keys[cls.Nr])

        return cls.matrix2bytes(state)

    @classmethod
    def decrypt_block(cls, ciphertext, round_keys):
        """Decrypt a single 16-byte block."""
        state = cls.bytes2matrix(ciphertext)
        cls.add_round_key(state, round_keys[cls.Nr])
        cls.inv_shift_rows(state)
        cls.inv_sub_bytes(state)

        for rnd in range(cls.Nr-1, 0, -1):
            cls.add_round_key(state, round_keys[rnd])
            cls.inv_mix_columns(state)
            cls.inv_shift_rows(state)
            cls.inv_sub_bytes(state)

        cls.add_round_key(state, round_keys[0])
        return cls.matrix2bytes(state)

    @classmethod
    def sub_bytes(cls, state):
        """Apply S-box substitution to state matrix."""
        for i in range(4):
            for j in range(4):
                state[i][j] = cls.sbox[state[i][j]]

    @classmethod
    def inv_sub_bytes(cls, state):
        """Apply inverse S-box substitution to state matrix."""
        for i in range(4):
            for j in range(4):
                state[i][j] = cls.inv_sbox[state[i][j]]

    @staticmethod
    def shift_rows(state):
        """Shift rows of state matrix left."""
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]

    @staticmethod
    def inv_shift_rows(state):
        """Shift rows of state matrix right."""
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]

    @classmethod
    def mix_columns(cls, state):
        """Mix columns of state matrix (AES mix columns)."""
        for i in range(4):
            a = [state[r][i] for r in range(4)]
            state[0][i] = cls.mul(2,a[0]) ^ cls.mul(3,a[1]) ^ a[2] ^ a[3]
            state[1][i] = a[0] ^ cls.mul(2,a[1]) ^ cls.mul(3,a[2]) ^ a[3]
            state[2][i] = a[0] ^ a[1] ^ cls.mul(2,a[2]) ^ cls.mul(3,a[3])
            state[3][i] = cls.mul(3,a[0]) ^ a[1] ^ a[2] ^ cls.mul(2,a[3])

    @classmethod
    def inv_mix_columns(cls, state):
        """Inverse mix columns of state matrix."""
        for i in range(4):
            a = [state[r][i] for r in range(4)]
            state[0][i] = cls.mul(0x0e,a[0]) ^ cls.mul(0x0b,a[1]) ^ cls.mul(0x0d,a[2]) ^ cls.mul(0x09,a[3])
            state[1][i] = cls.mul(0x09,a[0]) ^ cls.mul(0x0e,a[1]) ^ cls.mul(0x0b,a[2]) ^ cls.mul(0x0d,a[3])
            state[2][i] = cls.mul(0x0d,a[0]) ^ cls.mul(0x09,a[1]) ^ cls.mul(0x0e,a[2]) ^ cls.mul(0x0b,a[3])
            state[3][i] = cls.mul(0x0b,a[0]) ^ cls.mul(0x0d,a[1]) ^ cls.mul(0x09,a[2]) ^ cls.mul(0x0e,a[3])

    @staticmethod
    def add_round_key(state, round_key):
        """XOR state matrix with round key."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]

    @classmethod
    def pad(cls, plaintext):
        """Apply PKCS#7 padding to plaintext."""
        pad_len = 16 - (len(plaintext) % 16)
        return plaintext + bytes([pad_len] * pad_len)

    @classmethod
    def unpad(cls, padded):
        """Remove PKCS#7 padding from plaintext."""
        pad_len = padded[-1]
        if 1 <= pad_len <= 16:
            return padded[:-pad_len]
        return padded

    @classmethod
    def aes_cbc_encrypt(cls, plaintext, key, iv):
        """Encrypt plaintext with AES-CBC."""
        plaintext = cls.pad(plaintext)
        round_keys = cls.key_expansion(key)
        ciphertext = b""
        prev = iv

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            block = bytes(a ^ b for a,b in zip(block, prev))
            enc = cls.encrypt_block(block, round_keys)
            ciphertext += enc
            prev = enc

        return ciphertext

    @classmethod
    def aes_cbc_decrypt(cls, ciphertext, key, iv):
        """Decrypt ciphertext with AES-CBC."""
        round_keys = cls.key_expansion(key)
        plaintext = b""
        prev = iv

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            dec = cls.decrypt_block(block, round_keys)
            dec = bytes(a ^ b for a,b in zip(dec, prev))
            plaintext += dec
            prev = block

        return cls.unpad(plaintext)

    @staticmethod
    def is_probable_prime(n, k=20):
        """Check if n is a probable prime using Miller-Rabin test."""
        if n < 2:
            return False
        small_primes = [2,3,5,7,11,13,17,19,23,29,31]
        for p in small_primes:
            if n % p == 0:
                return n == p
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for __ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def gen_prime_3mod4(bits):
        """Generate a prime of form 3 mod 4 with given bits."""
        while True:
            r = random.getrandbits(bits) | 1 | (1 << (bits - 1))
            if r % 4 != 3:
                continue
            if Task2.is_probable_prime(r, k=20):
                return r

    @classmethod
    def _bbs_init(cls, p, q):
        """Initialize BBS generator with primes p, q."""
        n = p * q
        while True:
            seed = random.randint(2, n-1)
            if math.gcd(seed, n) == 1:
                break
        x = pow(seed, 2, n)
        return n, x

    @classmethod
    def _bbs_next_bit(cls, x, n):
        """Generate next bit from BBS generator."""
        x = pow(x, 2, n)
        return x & 1, x

    @classmethod
    def _bbs_bits(cls, n, x, k):
        """Generate k bits from BBS generator."""
        out = []
        for _ in range(k):
            bit, x = cls._bbs_next_bit(x, n)
            out.append(bit)
        return out, x

    @staticmethod
    def _bits_to_bytes(bits):
        """Convert list of bits to bytes."""
        b = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i+j < len(bits):
                    byte = (byte<<1) | bits[i+j]
            b.append(byte)
        return bytes(b)

    @classmethod
    def generate_aes_key_bbs(cls, bits=256):
        """Generate AES key using BBS generator."""
        p = cls.gen_prime_3mod4(bits//2 + 8)
        q = cls.gen_prime_3mod4(bits//2 + 8)
        while p == q:
            q = cls.gen_prime_3mod4(bits//2 + 8)

        n, x = cls._bbs_init(p, q)
        key_bits, _ = cls._bbs_bits(n, x, bits)
        return cls._bits_to_bytes(key_bits[:bits])

    @staticmethod
    def egcd(a, b):
        """Compute extended GCD of a and b."""
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q = a // b
            a, b = b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    @staticmethod
    def modinv(a, m):
        """Compute modular inverse of a mod m."""
        g, x, _ = Task2.egcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % m

    @classmethod
    def generate_rsa_keypair(cls, bits=1024):
        """Generate RSA public and private key pair."""
        half = bits // 2
        p = cls.gen_prime_3mod4(half)
        q = cls.gen_prime_3mod4(half)
        while q == p:
            q = cls.gen_prime_3mod4(half)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if math.gcd(e, phi) != 1:
            return cls.generate_rsa_keypair(bits)
        d = cls.modinv(e, phi)
        return (n, e), (n, d, p, q)

    @staticmethod
    def rsa_encrypt(m, pubkey):
        """Encrypt integer message m with RSA public key."""
        n, e = pubkey
        return pow(m, e, n)

    @staticmethod
    def rsa_decrypt_standard(c, privkey):
        """Decrypt integer ciphertext with standard RSA."""
        n, d, p, q = privkey
        return pow(c, d, n)

    @staticmethod
    def rsa_decrypt_crt(c, privkey):
        """Decrypt integer ciphertext using CRT optimization."""
        n, d, p, q = privkey
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = Task2.modinv(q, p)
        m1 = pow(c % p, dp, p)
        m2 = pow(c % q, dq, q)
        h = (qinv * (m1 - m2)) % p
        m = (m2 + h * q) % n
        return m

    @classmethod
    def rsa_decrypt_comparison(cls):
        """Compare speed of standard RSA vs CRT RSA decryption."""
        import time
        print("\nRSA CRT Speed Comparison\n")
        pubkey, privkey = cls.generate_rsa_keypair(1024)
        n, e = pubkey
        message = random.randint(2, n - 1)
        c = cls.rsa_encrypt(message, pubkey)
        t1 = time.time()
        m1 = cls.rsa_decrypt_standard(c, privkey)
        t2 = time.time()
        t3 = time.time()
        m2 = cls.rsa_decrypt_crt(c, privkey)
        t4 = time.time()
        print(f"Standard RSA decrypt: {t2 - t1:.6f} seconds")
        print(f"CRT RSA decrypt:      {t4 - t3:.6f} seconds")
        speedup = (t2 - t1) / (t4 - t3) if (t4 - t3) > 0 else float('inf')
        print(f"\nSpeedup: {speedup:.2f}x faster using CRT\n")
        if m1 == m2 == message:
            print("Correctness: PASS")
        else:
            print("Correctness: FAIL")
            print("message:", message)
            print("standard:", m1)
            print("crt     :", m2)

    def run(self):
        """Run AES and RSA demonstration."""
        print("TASK 2: AES-256 CBC with BBS Key Gen\n")
        key = self.generate_aes_key_bbs(256)
        iv = os.urandom(16)
        print(f"AES-256 Key (BBS): {key.hex()}")
        print(f"IV: {iv.hex()}\n")
        message = input("Enter your secret message: ")
        plaintext = message.encode()
        ciphertext = self.aes_cbc_encrypt(plaintext, key, iv)
        print(f"\nCiphertext (hex): {ciphertext.hex()}\n")
        decrypted = self.aes_cbc_decrypt(ciphertext, key, iv)
        print(f"Decrypted: {decrypted.decode()}")
        print("\nEncrypt/decrypt success!" if decrypted == plaintext else "\nFAILED")
        print("\n\nRSA with and without CRT")
        self.rsa_decrypt_comparison()

if __name__ == "__main__":
    Task2().run()
