#!/usr/bin/env python3
# solve.py

from pwn import *
from sage.all import *
import random

# --- Connection Details ---
# HOST = "localhost"
# PORT = 1337
HOST = "0.cloud.chals.io"
PORT = 19964

# --- Cryptosystem Parameters ---
E = 65537
NBIT = 512
R_BIT = NBIT >> 1 # 256

def jam(x, y, d, n):
    """
    Performs the 'jam' operation, equivalent to multiplication
    in the quadratic field Z_n[sqrt(d)].
    """
    x1, y1 = x
    x2, y2 = y
    _jam = (x1 * x2 + d * y1 * y2, x1 * y2 + x2 * y1)
    return (_jam[0] % n, _jam[1] % n)

def jam_pow(base, exp, d, n):
    """
    Performs exponentiation using the 'jam' operation,
    via the exponentiation by squaring method.
    """
    res = (1, 0)
    while exp > 0:
        if exp % 2 == 1:
            res = jam(res, base, d, n)
        base = jam(base, base, d, n)
        exp //= 2
    return res

def find_factor(n, hints, d=8):
    """
    Attempts to find a factor of n using a lattice attack on a subset of hints.
    """
    log.info(f"Attempting to find factor with subset size d={d}")
    # Heuristic scaling factor
    C = d * (2**R_BIT)

    # Build the lattice basis matrix B
    matrix_rows = [[n] + [0]*d]
    for i in range(d):
        row = [hints[i]] + [0]*d
        row[i+1] = C
        matrix_rows.append(row)
    
    B = Matrix(ZZ, matrix_rows)
    
    # Run LLL algorithm
    lll_basis = B.LLL()
    
    # The first vector in the LLL reduced basis is expected to be short.
    # We check several vectors from the reduced basis for robustness.
    for row in lll_basis:
        # Reconstruct the coefficients of the linear combination
        coeffs = [val / C for val in row[1:]]
        
        # Check if coefficients are integers, as expected
        if not all(c.is_integer() for c in coeffs):
            continue

        # Calculate the linear combination T = sum(coeffs_i * h_i)
        T = sum(int(coeffs[i]) * hints[i] for i in range(d))

        # The GCD of T and n may reveal a factor
        g = gcd(T, n)
        if 1 < g < n:
            log.success(f"Factor found: {g}")
            return g
            
    return None

def main():
    io = remote(HOST, PORT)

    # --- Step 1: Gather Data ---
    io.recvuntil(b"| Options: \n")
    io.sendline(b"I") # Request information
    
    # Receive and parse n (pkey)
    io.recvuntil(b"pkey = ")
    n = int(io.recvline().strip())
    log.info(f"Received n = {n}")
    
    # Receive and parse encrypted flag
    io.recvuntil(b"encrypted_flag = ")
    enc_flag_str = io.recvline().strip().decode()
    enc_flag = eval(enc_flag_str)
    log.info(f"Received encrypted_flag = {enc_flag}")

    # --- Step 2: Get Polished Numbers (Hints) ---
    io.recvuntil(b"| Options: \n")
    io.sendline(b"P")
    io.recvuntil(b"burnish the key: \n")
    # Request a large number of hints to maximize our chances
    num_polish = 80
    io.sendline(str(num_polish).encode())

    pls_hints = []
    while len(pls_hints) < num_polish:
        try:
            line = io.recvline().decode()
            if "PLS[" in line:
                val = int(line.split(" = ")[1])
                pls_hints.append(val)
            elif "| Options:" in line:
                break # All hints received
        except (ValueError, IndexError):
            continue
    log.info(f"Received {len(pls_hints)} polished hints.")

    # --- Step 3: Factor n using Lattice Attack ---
    p = None
    attempts = 0
    # We may need to try many random subsets
    while p is None and attempts < 200:
        attempts += 1
        log.info(f"Starting attempt #{attempts}")
        # Randomly select a subset of hints
        subset = random.sample(pls_hints, 8)
        p = find_factor(n, subset, d=8)
        if p is None:
            # try with a different subset size
            subset = random.sample(pls_hints, 10)
            p = find_factor(n, subset, d=10)

    if p is None:
        log.failure("Failed to find a factor after many attempts.")
        io.close()
        return

    q = n // p
    assert p * q == n
    log.success(f"Successfully factored n!")
    log.info(f"p = {p}")
    log.info(f"q = {q}")

    # --- Step 4: Decrypt the Flag ---
    # We have skey = (p, q). Now we re-implement the decryption logic.
    phi = (p - 1) * (q - 1)
    lambda_n = lcm(p-1, q-1)
    d_e = inverse_mod(E, lambda_n)

    c_tuple, f = enc_flag
    
    # Calculate a = f^(d_e) mod n
    a = pow(f, d_e, n)
    # Calculate d = a^2 mod n
    d_val = pow(a, 2, n)
    
    # Calculate (u, m) = c^(d_e) using jam_pow
    u, m = jam_pow(c_tuple, d_e, d_val, n)

    flag = long_to_bytes(m)
    log.success(f"FLAG: {flag.decode()}")
    
    io.close()

if __name__ == "__main__":
    main()
