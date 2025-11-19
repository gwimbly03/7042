import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from task2 import Task2


def generate_rsa_keypair():
    key = RSA.generate(2048, e=65537)
    return key, key.publickey()


def rsa_encrypt_aes_key(bob_public_key, aes_key):
    cipher = PKCS1_OAEP.new(bob_public_key)
    return cipher.encrypt(aes_key)


def rsa_decrypt_aes_key(bob_private_key, encrypted_key):
    cipher = PKCS1_OAEP.new(bob_private_key)
    return cipher.decrypt(encrypted_key)


def encrypt_image_file(image_path, aes_key):
    with open(image_path, "rb") as f:
        plaintext = f.read()

    iv = os.urandom(16)
    ciphertext = Task2.aes_cbc_encrypt(plaintext, aes_key, iv)

    encrypted_path = "encrypted_image.bin"
    with open(encrypted_path, "wb") as f:
        f.write(iv + ciphertext)

    return encrypted_path, iv, len(plaintext)


def decrypt_image_file(encrypted_path, aes_key):
    with open(encrypted_path, "rb") as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    decrypted_bytes = Task2.aes_cbc_decrypt(ciphertext, aes_key, iv)

    decrypted_path = "decrypted_image.png"
    with open(decrypted_path, "wb") as f:
        f.write(decrypted_bytes)

    return decrypted_path, decrypted_bytes


def main():
    image_path="./banana_fish.png"
    print("task4 - Image Encryption Using AES")

    if not os.path.exists(image_path):
        print(f"Error: Image not found: {image_path}")
        print("Please make sure the file exists and path is correct.")
        return

    bob_private_key, bob_public_key = generate_rsa_keypair()
    print(f"Bob generated 2048-bit RSA key (n = {bob_private_key.n.bit_length()} bits)")

    print("\nAlice generating 256-bit AES key using Blum-Blum-Shub PRNG...")
    aes_key = Task2.generate_aes_key_bbs()
    print(f"AES Key: {aes_key.hex()}")

    print("\nAlice encrypting AES key with Bob's public key (RSA-OAEP)...")
    encrypted_key = rsa_encrypt_aes_key(bob_public_key, aes_key)
    received_key = rsa_decrypt_aes_key(bob_private_key, encrypted_key)
    print(f"Bob recovered key: {'Success' if received_key == aes_key else 'Failed'}")

    print(f"\nAlice encrypting image: {image_path}")
    encrypted_file, iv, size = encrypt_image_file(image_path, received_key)
    print(f"Encrypted = {encrypted_file} ({size:,} bytes)")

    print(f"\nBob decrypting {encrypted_file}...")
    decrypted_file, decrypted_data = decrypt_image_file(encrypted_file, received_key)
    print(f"Decrypted = {decrypted_file}")

    with open(image_path, "rb") as f:
        original_data = f.read()

    if decrypted_data == original_data:
        print("Image decrypted")
    else:
        print("Decryption failed")


if __name__ == "__main__":
    main()
