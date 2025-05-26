from pwn import *

# Koneksi ke server
host = '0.cloud.chals.io'
port = 20671

# Membuat koneksi
conn = remote(host, port)

def send_command(command):
    conn.sendline(command)
    response = conn.recvuntil("Enter your choice:")  # Tunggu hingga menu muncul lagi
    print(response.decode())
    return response

def main():
    # Menjalankan perintah
    send_command('1')  # Telemetry
    send_command('2')  # Capture Image
    send_command('4')  # Switch panel state (Open)
    
    # Ambil gambar beberapa kali
    for _ in range(5):  # Ambil gambar 5 kali
        send_command('2')  # Capture Image
        
    send_command('3')  # Manage Power
    
    # Cek Telemetry untuk melihat apakah ada perubahan
    send_command('1')  # Telemetry

    # Coba untuk mendapatkan flag
    # Anda mungkin perlu menambahkan perintah lain di sini
    # Misalnya, coba untuk mengelola daya atau mengubah status panel lagi

if __name__ == "__main__":
    main()
