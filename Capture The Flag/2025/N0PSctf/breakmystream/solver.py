#!/usr/bin/env python3
from pwn import *

# Menggunakan fungsi xor bawaan pwntools yang andal
# HOST dan PORT dari tantangan
HOST = "0.cloud.chals.io"
PORT = 31561

# Memulai koneksi ke server
log.info(f"Connecting to {HOST}:{PORT}")
r = remote(HOST, PORT)

# 1. Menerima output awal dan mengekstrak flag yang terenkripsi
r.recvuntil(b"Oh, one last thing: ")
encrypted_flag_hex = r.recvline().strip().decode()
log.info(f"Encrypted Flag (hex): {encrypted_flag_hex}")

# Mengonversi flag dari hex ke bytes
encrypted_flag = bytes.fromhex(encrypted_flag_hex)
flag_len = len(encrypted_flag)
log.info(f"Panjang flag: {flag_len} bytes")

# 2. Membuat plaintext yang kita ketahui (string 'A' diulang)
# Ini adalah plaintext yang akan kita kirim untuk membocorkan keystream
known_plaintext = b'A' * flag_len
log.info(f"Mengirim known plaintext: {known_plaintext}")

# 3. Mengirim plaintext kita ke server untuk dienkripsi
r.sendlineafter(b"Enter your message: ", known_plaintext)

# 4. Menerima hasil enkripsi dari plaintext kita (dalam format hex)
leaked_ciphertext_hex = r.recvline().strip().decode()
leaked_ciphertext = bytes.fromhex(leaked_ciphertext_hex)
log.info(f"Ciphertext yang diterima (hex): {leaked_ciphertext_hex}")

# 5. Memulihkan keystream
# Keystream = LeakedCiphertext XOR KnownPlaintext
keystream = xor(leaked_ciphertext, known_plaintext)
log.info(f"Keystream yang dipulihkan (hex): {keystream.hex()}")

# 6. Mendekripsi flag menggunakan keystream yang telah dipulihkan
# Flag = EncryptedFlag XOR Keystream
decrypted_flag = xor(encrypted_flag, keystream)

# 7. Menampilkan flag yang berhasil didekripsi
log.success(f"Flag: {decrypted_flag.decode()}")

# Menutup koneksi
r.close()
