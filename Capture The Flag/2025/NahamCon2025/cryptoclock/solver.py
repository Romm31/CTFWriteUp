#!/usr/bin/env python3
import socket
import random
from typing import Optional

# Copied from server.py for utility
def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data using XOR with the given key."""
    return bytes(a ^ b for a, b in zip(data, key))

def generate_key(length: int, seed: Optional[float] = None) -> bytes:
    """Generate a random key of given length using the provided seed."""
    if seed is not None:
        random.seed(int(seed)) # Server uses int(time.time()) as seed
    return bytes(random.randint(0, 255) for _ in range(length))

def solve():
    HOST = "challenge.nahamcon.com"
    PORT = 30265

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"[*] Connected to {HOST}:{PORT}")

        # 1. Receive welcome message and encrypted flag
        welcome_data = client_socket.recv(4096)
        # print(f"[*] Received welcome: {welcome_data.decode(errors='ignore')}")

        # 2. Extract encrypted flag hex
        hex_flag_str = ""
        try:
            for line in welcome_data.split(b'\n'):
                if b"The encrypted flag is: " in line:
                    hex_flag_str = line.decode().split("The encrypted flag is: ")[1].strip()
                    break
            if not hex_flag_str:
                print("[-] Error: Could not find encrypted flag in welcome message.")
                return
        except IndexError:
            print("[-] Error: Malformed encrypted flag line.")
            print(f"Raw welcome data: {welcome_data}")
            return
            
        encrypted_flag_bytes = bytes.fromhex(hex_flag_str)
        flag_len = len(encrypted_flag_bytes)
        print(f"[*] Parsed encrypted flag (hex): {hex_flag_str}")
        print(f"[*] Deduced flag length: {flag_len}")

        if flag_len == 0:
            print("[-] Error: Flag length is 0. Cannot proceed.")
            return

        # 3. Choose a known plaintext of the same length as the flag
        known_plaintext = b'A' * flag_len
        
        # 4. Send the known plaintext (server expects a newline to process input)
        # print(f"[*] Sending known plaintext (length {len(known_plaintext)}): {known_plaintext.decode(errors='ignore')}")
        client_socket.sendall(known_plaintext + b'\n')

        # 5. Receive the encrypted version of our known plaintext
        response_data = client_socket.recv(4096)
        # print(f"[*] Received response for known plaintext: {response_data.decode(errors='ignore')}")

        # 6. Extract the encrypted known plaintext
        hex_known_encrypted_str = ""
        try:
            if b"Encrypted: " in response_data:
                 hex_known_encrypted_str = response_data.split(b"Encrypted: ")[1].split(b'\n')[0].decode().strip()
            if not hex_known_encrypted_str:
                print("[-] Error: Could not find encrypted known plaintext in response.")
                return
        except IndexError:
            print("[-] Error: Malformed encrypted data line.")
            print(f"Raw response data: {response_data}")
            return

        encrypted_known_plaintext_bytes = bytes.fromhex(hex_known_encrypted_str)
        # print(f"[*] Parsed encrypted known plaintext (hex): {hex_known_encrypted_str}")

        if len(encrypted_known_plaintext_bytes) != flag_len:
            print(f"[-] Error: Length mismatch! Encrypted known plaintext length is {len(encrypted_known_plaintext_bytes)}, expected {flag_len}")
            return

        # 7. Decrypt the flag
        # flag = encrypted_flag_bytes XOR known_plaintext XOR encrypted_known_plaintext_bytes
        
        decrypted_flag_bytes = bytes(b1 ^ b2 ^ b3 for b1, b2, b3 in zip(encrypted_flag_bytes, known_plaintext, encrypted_known_plaintext_bytes))
        
        print(f"\n[+] Potential Flag: {decrypted_flag_bytes.decode(errors='replace')}")

        # 8. Send quit command (optional, good practice)
        client_socket.sendall(b'quit\n')

    except socket.error as e:
        print(f"[-] Socket error: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
    finally:
        if 'client_socket' in locals():
            client_socket.close()
            # print("[*] Connection closed.")

if __name__ == "__main__":
    solve()
