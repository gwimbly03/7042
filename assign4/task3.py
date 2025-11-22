import os
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from task1 import generate_rsa_key  

def extended_gcd(a, b):
    """Compute the extended GCD of a and b and return (gcd, x, y)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def invmod(a, m):
    """Compute the modular inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

def rsa_crt_decrypt_integer(c, d, p, q, n):
    """Decrypt an integer ciphertext using RSA with CRT optimization."""
    dP = d % (p - 1)
    dQ = d % (q - 1)
    qInv = pow(q, -1, p)   

    m1 = pow(c, dP, p)
    m2 = pow(c, dQ, q)

    h = (qInv * (m1 - m2)) % p
    m = m2 + h * q
    return m

def rsa_standard_decrypt_integer(cipher_int, d, n):
    """Decrypt an integer ciphertext using standard RSA decryption."""
    return pow(cipher_int, d, n)

def main():
    """Generate RSA keypair, encrypt/decrypt AES key, and compare CRT vs standard RSA."""
    PRIME_BITS = 2048  
    print(f"Generating RSA keypair ({PRIME_BITS} bits per prime) using Task1")
    t0 = time.time()
    res = generate_rsa_key(PRIME_BITS, mr_rounds=16)
    t1 = time.time()
    print(f"Done in {t1 - t0:.2f}s. Attempts: {res['attempts']}\n")

    p = res["rsa_p"]
    q = res["rsa_q"]
    n = res["n"]
    e = res["e"]
    d = res["d"]

    print("RSA key components (sample):")
    print(f"  n bits: {n.bit_length()}")
    print(f"  e: {e}")
    print(f"  d bits: {d.bit_length()}")
    print(f"  p bits: {p.bit_length()}, q bits: {q.bit_length()}\n")

    key = RSA.construct((n, e, d, p, q))
    pubkey = key.publickey()

    aes_key = get_random_bytes(32)
    print("Generated AES-256 key (hex):", aes_key.hex())

    oaep_enc = PKCS1_OAEP.new(pubkey)
    ciphertext = oaep_enc.encrypt(aes_key)
    print("\nEncrypted AES key with RSA-OAEP (hex, truncated):", ciphertext.hex()[:160], "...")
    print(f"Encrypted length: {len(ciphertext)} bytes\n")

    oaep_dec = PKCS1_OAEP.new(key)
    decrypted = oaep_dec.decrypt(ciphertext)
    print("Decrypted AES key (hex):", decrypted.hex())
    print("AES key match:", "PASS" if decrypted == aes_key else "FAIL")

    cipher_int = int.from_bytes(ciphertext, byteorder='big')

    _ = rsa_standard_decrypt_integer(cipher_int, d, n)
    _ = rsa_crt_decrypt_integer(cipher_int, d, p, q, n)

    runs = 50
    t_std_start = time.time()
    for _ in range(runs):
        m_std = rsa_standard_decrypt_integer(cipher_int, d, n)
    t_std_end = time.time()

    t_crt_start = time.time()
    for _ in range(runs):
        m_crt = rsa_crt_decrypt_integer(cipher_int, d, p, q, n)
    t_crt_end = time.time()

    std_ms = (t_std_end - t_std_start) * 1000
    crt_ms = (t_crt_end - t_crt_start) * 1000
    speedup = std_ms / crt_ms if crt_ms > 0 else float('inf')

    print("\nRSA modular-exponentiation timings ({} runs)".format(runs))
    print(f"Standard modular-exponent total: {std_ms:.2f} ms")
    print(f"CRT modular-exponent total:      {crt_ms:.2f} ms")
    print(f"Speedup (std / crt): {speedup:.2f}x\n")

    equal = (m_std == m_crt)
    print("Integer modular-exponent results equal:", "PASS" if equal else "FAIL")
    if not equal:
        print("standard result (hex, truncated):", hex(m_std)[:120])
        print("crt result      (hex, truncated):", hex(m_crt)[:120])

    klen = (n.bit_length() + 7) // 8
    recovered_padded = m_std.to_bytes(klen, byteorder='big')
    print("\nRecovered padded block length (bytes):", len(recovered_padded))

if __name__ == "__main__":
    main()

