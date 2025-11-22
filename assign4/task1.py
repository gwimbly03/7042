import os
import math
import random
import zlib
from time import time

def is_probable_prime(n, k=20):
    """Return True if n is probably prime using Miller-Rabin test."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def extended_gcd(a, b):
    """Return (gcd, x, y) such that ax + by = gcd."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def invmod(a, m):
    """Return modular inverse of a modulo m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def bbs_init(p, q, seed=None):
    """Initialize BBS generator and return (n, x)."""
    assert p % 4 == 3 and q % 4 == 3, "p and q must be 3 mod 4"
    n = p * q
    if seed is None:
        while True:
            seed = random.randrange(2, n - 1)
            if math.gcd(seed, n) == 1:
                break
    x = pow(seed, 2, n)
    return n, x


def bbs_next_bit(x, n):
    """Return next bit and updated state from BBS."""
    x = pow(x, 2, n)
    return x & 1, x


def bbs_bits(n, x, k):
    """Generate k bits from BBS and return updated state."""
    bits = []
    for _ in range(k):
        bit, x = bbs_next_bit(x, n)
        bits.append(bit)
    return bits, x


def candidate_from_bbs(n, x, bits):
    """Generate integer candidate from BBS bits."""
    raw_bits, x = bbs_bits(n, x, bits)
    raw_bits[0] = 1
    raw_bits[-1] = 1
    val = 0
    for bit in raw_bits:
        val = (val << 1) | bit
    return val, x


def generate_prime_with_bbs(n, x, bits, mr_rounds=20):
    """Generate a probable prime using BBS and Miller-Rabin."""
    attempts = 0
    while True:
        attempts += 1
        cand, x = candidate_from_bbs(n, x, bits)
        if all(cand % p != 0 for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]):
            if is_probable_prime(cand, k=mr_rounds):
                return cand, attempts, x


def generate_rsa_key(bits=512, mr_rounds=20):
    """Generate RSA keypair using BBS-generated primes."""
    def gen_3mod4(bits):
        while True:
            r = random.getrandbits(bits) | 1 | (1 << (bits - 1))
            if r % 4 == 3 and is_probable_prime(r, k=mr_rounds):
                return r

    p_bbs = gen_3mod4(bits // 2)
    q_bbs = gen_3mod4(bits // 2)
    n_bbs, x = bbs_init(p_bbs, q_bbs)

    rsa_p, a1, x = generate_prime_with_bbs(n_bbs, x, bits, mr_rounds)
    rsa_q, a2, x = generate_prime_with_bbs(n_bbs, x, bits, mr_rounds)
    while rsa_q == rsa_p:
        rsa_q, a2, x = generate_prime_with_bbs(n_bbs, x, bits, mr_rounds)

    n = rsa_p * rsa_q
    phi = (rsa_p - 1) * (rsa_q - 1)
    e = 65537
    d = invmod(e, phi)

    return {
        "p_bbs": p_bbs, "q_bbs": q_bbs, "n_bbs": n_bbs,
        "rsa_p": rsa_p, "rsa_q": rsa_q,
        "n": n, "e": e, "d": d,
        "attempts": (a1, a2),
        "bbs_x": x
    }


def frequency_monobit_test(bits):
    """Perform the NIST frequency (monobit) test and return p-value."""
    n = len(bits)
    s = sum(1 if b == 1 else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))
    return p_value, s


def runs_test(bits):
    """Perform the NIST runs test and return p-value and run count."""
    n = len(bits)
    pi = sum(bits) / n
    tau = 2 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return 0.0, None
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i-1]:
            runs += 1
    expected = 2 * n * pi * (1 - pi)
    var = 2 * n * pi * (1 - pi) * (2 * n * pi * (1 - pi) - 1) / (n - 1)
    z = abs(runs - expected) / math.sqrt(var)
    p_value = math.erfc(z / math.sqrt(2))
    return p_value, runs


def maurer_universal_approx(bits, L=6):
    """Perform the Maurer Universal test and return test statistic."""
    n = len(bits)
    Q = 10 * (1 << L)
    K = (n // L) - Q
    if K <= 0:
        raise ValueError("Sequence too short for Maurer test")

    last = [-1] * (1 << L)
    bit_index = 0
    for i in range(Q):
        block = 0
        for j in range(L):
            block = (block << 1) | bits[bit_index]
            bit_index += 1
        last[block] = i + 1

    sum_log = 0.0
    for i in range(K):
        block = 0
        for j in range(L):
            block = (block << 1) | bits[bit_index]
            bit_index += 1
        prev = last[block]
        distance = (i + Q + 1) - prev if prev != -1 else i + Q + 1
        last[block] = i + Q + 1
        sum_log += math.log2(distance)
    return sum_log / K, {"L": L, "Q": Q, "K": K}


def main():
    """Generate RSA keys, run NIST randomness tests, and print results."""
    PRIME_BITS = 2048 
    TEST_BITS = 200000
    MR_ROUNDS = 16

    print(f"Generating RSA keypair ({PRIME_BITS} bits per prime)")
    start = time()
    res = generate_rsa_key(PRIME_BITS, MR_ROUNDS)
    print(f"Done in {time() - start:.2f}s. Attempts for primes: {res['attempts']}\n")

    print("RSA Key Gen")
    print("n bits:", res["n"].bit_length())
    print("e:", res["e"])
    print("d bits:", res["d"].bit_length())
    print("Sample p,q bits:", res["rsa_p"].bit_length(), res["rsa_q"].bit_length())

    bits, _ = bbs_bits(res["n_bbs"], res["bbs_x"], TEST_BITS)
    print(f"\nGenerated {len(bits)} bits for NIST randomness tests.")

    p_freq, s_val = frequency_monobit_test(bits)
    print("\nFrequency Test")
    print(f"Sum S = {s_val}, average = {p_freq:.6f}")
    print("Result:", "PASS" if p_freq >= 0.01 else "FAIL")

    p_runs, run_count = runs_test(bits)
    print("\nMiller Rabin Test")
    print(f"Times MR ran = {run_count}, average = {p_runs:.6f}")
    print("Result:", "PASS" if p_runs >= 0.01 else "FAIL")

    try:
        fn, info = maurer_universal_approx(bits)
        print("\nMaurer Universal Test")
        print(f"fn = {fn}, info = {info}")
    except ValueError as e:
        print("\nMaurer Test could not run:", e)

    b = bytes((int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)))
    compressed = zlib.compress(b)
    ratio = len(compressed) / len(b)
    print("\nCompression Test")
    print(f"Raw bytes: {len(b)}, Compressed: {len(compressed)}, Ratio: {ratio:.4f}")

    print("\nPublic key:")
    print("n (hex, first 200 chars):", hex(res["n"])[2:202])
    print("e:", res["e"])


if __name__ == "__main__":
    main()

