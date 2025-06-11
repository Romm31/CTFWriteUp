import math
import socket

# --- Konfigurasi Server ---
HOST = '0.cloud.chals.io'
PORT = 13055

def solve_path_hybrid():
    """
    Menyelesaikan masalah dengan pendekatan hibrida:
    1. Membuat jalur awal yang baik dengan Nearest Neighbor.
    2. Menyempurnakan jalur tersebut dengan 2-Opt.
    """
    points = [
        (0, 0), # Beehive
        (-62, -67), (-8, 44), (44, 17), (-91, -74), (-56, 18), (96, -19),
        (45, -67), (-28, 62), (94, 69), (48, 52), (-11, 64), (-95, -57),
        (-2, 79), (34, 40), (-5, 24), (-35, -50), (-40, 72), (-25, -4),
        (-75, -98), (6, 98), (-87, -37), (-63, 99), (-96, 86), (28, 65),
        (-87, 26), (53, -2), (-98, 7), (69, -71), (18, 41), (-84, 51),
        (-80, -10), (50, 39), (13, -89), (4, 35), (31, 95), (84, -50),
        (86, -82), (32, -21), (-36, -22), (34, -77), (-77, -78), (-92, -2),
        (72, -54), (88, -29), (1, -14), (-82, 97), (-16, -70), (-19, 96),
        (-41, 41), (-24, -87)
    ]
    num_points = len(points)

    def euclidean_distance(p1, p2):
        return math.sqrt((p1[0] - p2[0])**2 + (p1[1] - p2[1])**2)

    def calculate_path_distance(path, points_data):
        total_dist = 0
        for i in range(len(path) - 1):
            total_dist += euclidean_distance(points_data[path[i]], points_data[path[i+1]])
        return total_dist

    # --- Langkah 1: Greedy Nearest Neighbor untuk jalur awal ---
    print("Mulai menghitung jalur awal dengan Nearest Neighbor...")
    unvisited = set(range(1, num_points))
    initial_path = [0]
    current_idx = 0
    while unvisited:
        nearest_dist = float('inf')
        nearest_idx = -1
        for idx in unvisited:
            dist = euclidean_distance(points[current_idx], points[idx])
            if dist < nearest_dist:
                nearest_dist = dist
                nearest_idx = idx
        current_idx = nearest_idx
        initial_path.append(current_idx)
        unvisited.remove(current_idx)

    print("✅ Jalur awal selesai dibuat.")

    # --- Langkah 2: 2-Opt Refinement ---
    print("Mulai menyempurnakan jalur dengan 2-Opt...")
    current_path = initial_path
    improved = True
    while improved:
        improved = False
        best_distance = calculate_path_distance(current_path + [0], points)
        for i in range(1, num_points - 2):
            for j in range(i + 2, num_points):
                new_path = current_path[:i] + current_path[i:j+1][::-1] + current_path[j+1:]
                new_distance = calculate_path_distance(new_path + [0], points)
                if new_distance < best_distance:
                    current_path = new_path
                    best_distance = new_distance
                    improved = True
                    # Keluar dari loop dalam untuk memulai lagi dari awal
                    # dengan jalur baru yang lebih baik
                    break
            if improved:
                break
    
    final_path = current_path + [0]
    final_distance = calculate_path_distance(final_path, points)
    
    print(f"✅ Perhitungan selesai. Panjang jalur final: {final_distance:.2f}")

    if final_distance >= 1400:
        print("❌ PERINGATAN: Jalur yang ditemukan masih terlalu panjang. Ini tidak seharusnya terjadi.")
    else:
        print("✅ Jalur yang ditemukan di bawah 1400. Seharusnya berhasil!")

    return " ".join(map(str, final_path))

def submit_solution(host, port, solution_string):
    print(f"\nMenghubungkan ke {host}:{port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            print("✅ Berhasil terhubung.")
            initial_prompt = s.recv(1024).decode()
            print(f"Server: {initial_prompt.strip()}")
            s.sendall(solution_string.encode() + b'\n')
            response = s.recv(1024).decode()
            print("\n-------------------[ RESPON SERVER ]-------------------")
            print(response.strip())
            print("------------------------------------------------------")
    except Exception as e:
        print(f"❌ Terjadi error: {e}")

if __name__ == '__main__':
    solution = solve_path_hybrid()
    if solution:
        submit_solution(HOST, PORT, solution)
