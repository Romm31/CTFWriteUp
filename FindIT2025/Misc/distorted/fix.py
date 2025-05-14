from PIL import Image
import numpy as np

# Buka gambar
img = Image.open("location.png")
img_array = np.array(img)

# Siapkan array kosong untuk hasil
fixed_array = np.zeros_like(img_array)

# Geser setiap baris ke kiri sesuai urutan (dengan offset 5 piksel per baris)
for y in range(img_array.shape[0]):
    offset = (y * 5) % img_array.shape[1]
    fixed_array[y] = np.roll(img_array[y], -offset, axis=0)  # geser ke kiri

# Simpan gambar hasil
fixed_img = Image.fromarray(fixed_array)
fixed_img.save("fixed_location.png")
fixed_img.show()
