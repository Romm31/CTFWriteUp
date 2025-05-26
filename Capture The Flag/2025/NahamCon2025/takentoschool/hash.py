import re

# Baca isi file
with open('network-log.cef', 'r') as f:
    content = f.read()

# Cari semua hash dari field eventHash=
hashes = re.findall(r'eventHash=([0-9a-fA-F]{32})', content)

# Buat list flag{hash}
flags = [f"flag{{{h}}}" for h in hashes]

# Hilangkan duplikat (jika ada)
unique_flags = sorted(set(flags))

# Simpan ke file
with open('extracted_flags.txt', 'w') as f:
    for flag in unique_flags:
        f.write(flag + '\n')

print(f"{len(unique_flags)} flags berhasil diekstrak dan disimpan ke extracted_flags.txt")
