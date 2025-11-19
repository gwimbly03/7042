import random

def invmod(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)

def rsa_encrypt(message_int, e, n):
    return pow(message_int, e, n)

def rsa_decrypt(cipher_int, d, n):
    return pow(cipher_int, d, n)

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(i, length):
    return i.to_bytes(length, byteorder='big')

def simulate_rsa_key_exchange():
    e = 65537
    p = 2957
    q = 3557
    n = p * q
    phi = (p - 1) * (q - 1)
    d = invmod(e, phi)

    print(f"RSA Public Key (n, e): ({n}, {e})")
    print(f"RSA Private Key (d): {d}")

    aes_key = b'ThisIs32ByteLongAESKeyForDemo!'  # 32 bytes = 256-bit key
    print("\nOriginal AES Key:", aes_key.hex())

    key_int = bytes_to_int(aes_key)

    encrypted_key_int = rsa_encrypt(key_int, e, n)
    print("Encrypted AES Key (int):", encrypted_key_int)

    decrypted_key_int = rsa_decrypt(encrypted_key_int, d, n)

    decrypted_aes_key = int_to_bytes(decrypted_key_int, len(aes_key))
    print("Decrypted AES Key:", decrypted_aes_key.hex())

    if decrypted_aes_key == aes_key:
        print("Success: AES key correctly retrieved via RSA key exchange!")
    else:
        print("Failure: Decrypted key does not match original AES key.")

simulate_rsa_key_exchange()

