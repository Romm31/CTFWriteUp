#!/usr/bin/env python3
# solver.py

import pwn
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

# --- Connection Details ---
HOST = '0.cloud.chals.io'
PORT = 26625
N_BYTES = 1024 

def solve():
    """
    Connects to the server, exploits the Diffie-Hellman implementation,
    and saves the decrypted flag data to a file.
    """
    # Establish connection to the server
    conn = pwn.remote(HOST, PORT)

    # --- Step 1: Receive server's public parameters ---
    pwn.log.info("Receiving public parameters from server...")
    p = int.from_bytes(conn.recv(N_BYTES), 'big')
    g = int.from_bytes(conn.recv(N_BYTES), 'big')
    k_a = int.from_bytes(conn.recv(N_BYTES), 'big')
    pwn.log.success("Parameters received.")

    # --- Step 2: Send a malicious public key ---
    # We send k_b = 1 to force the shared secret to be 1.
    malicious_k_b = 1
    conn.send(malicious_k_b.to_bytes(N_BYTES, 'big'))
    pwn.log.info("Sent malicious public key (k_b = 1).")

    # --- Step 3: Calculate the predictable shared secret and AES key ---
    shared_secret_k = 1
    key_material = shared_secret_k.to_bytes((shared_secret_k.bit_length() + 7) // 8, 'big')
    aes_key = sha256(key_material).digest()
    pwn.log.info("Derived the predictable AES key.")

    # --- Step 4: Receive and decrypt the flag data ---
    encrypted_flag_data = conn.recvall()
    conn.close()

    iv = encrypted_flag_data[:AES.block_size]
    ciphertext = encrypted_flag_data[AES.block_size:]

    pwn.log.info("Received encrypted data. Decrypting...")
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_padded_data = cipher.decrypt(ciphertext)
    
    try:
        # Unpad the decrypted data to get the original file
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        pwn.log.success("Data decrypted and unpadded successfully.")

        # --- Step 5: Save the output file ---
        output_filename = "flag.png"
        with open(output_filename, "wb") as f:
            f.write(decrypted_data)
        
        pwn.log.success(f"Decrypted data saved to '{output_filename}'!")
        pwn.log.info("Open the image file to find the flag. 🚩")

    except ValueError as e:
        pwn.log.failure(f"Unpadding failed: {e}")
        pwn.log.info("This might indicate the decryption key is incorrect.")

if __name__ == "__main__":
    solve()
