import socket

# Konfigurasi koneksi
HOST = 'ctf.find-it.id'
PORT = 7101

# Fungsi untuk menghubungkan ke server dan mengirim input
def solve_challenge(input_string):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Menerima pesan awal
        response = s.recv(1024).decode()
        print(response)

        # Mengirim input
        s.sendall(input_string.encode() + b'\n')
        # Menerima respons dari server
        response = s.recv(1024).decode()
        print(response)

# Daftar variasi input yang akan dicoba
variations = [
    "Ayo Ayo Ganyang si b.e.b.a.n 🌸",  # Input asli
    "Ayo Ayo Ganyang si b.e.b.a.n",      # Tanpa emoji
    "Ayo Ayo Ganyang",                    # Menghapus bagian akhir
    "Ganyang si b.e.b.a.n 🌸",            # Mengubah urutan
    "Ganyang",                             # Hanya satu kata
    "Ayo Ayo",                            # Menghapus bagian akhir
    "Ayo Ayo Ganyang",                    # Menghapus bagian dari input
]

# Mencoba setiap variasi input
for variation in variations:
    print(f"Mencoba input: {variation}")
    solve_challenge(variation)
