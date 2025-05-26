import numpy as np
import itertools
import sympy # For GF(2) matrix operations

# --- Parameters ---
R_const = 6
N_const = 2**R_const - 1
K_const = N_const - R_const # 57

# --- Utility Functions (from previous attempt) ---
def string_to_bits(s):
    bits = []
    for ch in s:
        bits.extend(int(b) for b in format(ord(ch), '08b'))
    return bits

def bits_to_string(b_list):
    s = ""
    num_full_bytes = len(b_list) // 8
    for i in range(num_full_bytes):
        byte_bits = b_list[i*8 : (i+1)*8]
        s += chr(int("".join(map(str, byte_bits)), 2))
    if len(b_list) % 8 != 0:
        # This should ideally not happen if unpadding + message content is byte-aligned
        print(f"Warning: {len(b_list) % 8} trailing bits were not converted to characters.")
    return s

def unpad_message_bits(all_m_bits_list):
    try:
        last_one_index = len(all_m_bits_list) - 1 - all_m_bits_list[::-1].index(1)
        return all_m_bits_list[:last_one_index]
    except ValueError:
        print("Error: No '1' terminator found in combined message bits during unpadding.")
        return None

def hex_string_to_bit_list(hex_s, num_expected_bits):
    """
    Converts a hexadecimal string to a list of bits, ensuring the output
    has exactly num_expected_bits by appropriate zfill.
    """
    val = int(hex_s, 16)
    bit_s_raw = bin(val)[2:] # Raw binary string from the integer value

    # Pad with leading zeros to meet the num_expected_bits requirement
    # If bit_s_raw is longer than num_expected_bits, it means the hex value
    # is too large for the expected number of bits. This indicates an issue
    # if hex_s was supposed to be a minimal representation of num_expected_bits.
    if len(bit_s_raw) > num_expected_bits:
        print(f"Warning: Hex value {hex_s[:10]}... results in {len(bit_s_raw)} bits, but expected {num_expected_bits}. Taking last {num_expected_bits} bits.")
        # This might happen if num_expected_bits was underestimated.
        # For this problem, num_expected_bits (630) is derived to be consistent with
        # hex length (158) and N_const (63), implying len(bit_s_raw) <= 630.
        bit_s_final = bit_s_raw[len(bit_s_raw) - num_expected_bits:]
    else:
        bit_s_final = bit_s_raw.zfill(num_expected_bits)
        
    return [int(b) for b in bit_s_final]


def load_G_pub(filename="alice_pub.npy"):
    G_pub_loaded = np.load(filename)
    return G_pub_loaded.astype(int) % 2

# --- GF(2) Matrix Helper for Preprocessing G_pub ---
def get_G_inv_basis(G_matrix_np):
    K, N = G_matrix_np.shape
    G_sympy = sympy.Matrix(G_matrix_np.tolist())
    rref_matrix, pivot_cols = G_sympy.rref(iszerofunc=lambda x: x % 2 == 0)

    if len(pivot_cols) < K:
        print(f"Error: G_pub matrix does not have rank K={K}. Found rank {len(pivot_cols)}.")
        return None, None
    basis_indices = sorted(list(pivot_cols)[:K])
    G_sq_np = G_matrix_np[:, basis_indices]
    G_sq_sympy = sympy.Matrix(G_sq_np.tolist())
    try:
        G_sq_inv_sympy = G_sq_sympy.inv_mod(2)
        G_sq_inv_np = np.array(G_sq_inv_sympy.tolist(), dtype=int)
        return G_sq_inv_np, basis_indices
    except sympy.matrices.common.NonInvertibleMatrixError:
        print(f"Error: Submatrix G_sq formed by columns {basis_indices} is not invertible over GF(2).")
        return None, None

# --- Main Decoding Function for a Single Block ---
def decode_block_by_error_guessing(c_block_arr_1xN, G_pub_np_KxN, G_pub_sq_inv_np_KxK, basis_indices_list_K):
    N = G_pub_np_KxN.shape[1]
    for err_idx in range(N):
        c_candidate_arr = c_block_arr_1xN.copy()
        c_candidate_arr[err_idx] = 1 - c_candidate_arr[err_idx]
        c_candidate_sq_arr = c_candidate_arr[basis_indices_list_K]
        m_candidate_arr = (c_candidate_sq_arr @ G_pub_sq_inv_np_KxK) % 2
        reconstructed_c_arr = (m_candidate_arr @ G_pub_np_KxN) % 2
        if np.array_equal(reconstructed_c_arr, c_candidate_arr):
            return m_candidate_arr.tolist()
    
    # Fallback: Check original block (t=0 scenario)
    # Problem implies t=1 error is always added, so this path is unlikely to be the solution.
    c_candidate_sq_arr_orig = c_block_arr_1xN[basis_indices_list_K]
    m_candidate_arr_orig = (c_candidate_sq_arr_orig @ G_pub_sq_inv_np_KxK) % 2
    reconstructed_c_arr_orig = (m_candidate_arr_orig @ G_pub_np_KxN) % 2
    if np.array_equal(reconstructed_c_arr_orig, c_block_arr_1xN):
        print(f"Warning: Original block decoded without flipping. Error might have been effectively null for this block.")
        return m_candidate_arr_orig.tolist()

    print(f"Error: Could not decode block starting with {c_block_arr_1xN[:10].tolist()}...")
    return None

# --- Main Execution ---
if __name__ == "__main__":
    G_pub = load_G_pub()
    if G_pub.shape != (K_const, N_const):
        print(f"Error: Loaded G_pub has incorrect shape {G_pub.shape}. Expected ({K_const}, {N_const})")
        exit()

    print("Preprocessing G_pub to find invertible submatrix and its inverse...")
    G_pub_sq_inv, basis_indices = get_G_inv_basis(G_pub)

    if G_pub_sq_inv is None:
        print("Failed to preprocess G_pub. Exiting.")
        exit()
    print(f"Using basis columns (first 5 shown): {basis_indices[:5]}... (total {len(basis_indices)})")

    hex_ciphertext = "33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5"
    
    # Determine the actual number of bits based on hex length and N_const
    L_H = len(hex_ciphertext)
    # We derived L_data = 630 for L_H = 158 and N_const = 63
    total_actual_bits = 0
    min_bits_for_hex = (L_H - 1) * 4 + 1
    max_bits_for_hex = L_H * 4
    
    found_l_data = False
    for num_potential_blocks in range(1, (max_bits_for_hex // N_const) + 2):
        l_data_candidate = num_potential_blocks * N_const
        if min_bits_for_hex <= l_data_candidate <= max_bits_for_hex:
            if L_H == (l_data_candidate + 3) // 4: # Check if L_H is ceil(l_data_candidate/4)
                total_actual_bits = l_data_candidate
                found_l_data = True
                break
    
    if not found_l_data:
        print(f"Error: Could not consistently determine total_actual_bits from hex length {L_H} and N_const {N_const}.")
        # Defaulting to a common derivation if unique one not found above.
        # For L_H=158, N_const=63, we expect 630 bits.
        if L_H == 158 and N_const == 63: # Specific values from this problem
             total_actual_bits = 630
             print(f"Defaulting total_actual_bits to {total_actual_bits} based on known problem parameters.")
        else:
            exit()
    else:
        print(f"Determined total actual bits from hex string: {total_actual_bits}")

    all_cipher_bits_list = hex_string_to_bit_list(hex_ciphertext, total_actual_bits)
    
    if len(all_cipher_bits_list) % N_const != 0: # This check should now pass
        print(f"Critical Error: Total ciphertext bits {len(all_cipher_bits_list)} after correction is still not a multiple of N={N_const}.")
        exit()
    
    num_blocks = len(all_cipher_bits_list) // N_const
    print(f"Ciphertext contains {num_blocks} block(s) of {N_const} bits each.")
    
    cipher_blocks_np_list = [
        np.array(all_cipher_bits_list[i:i+N_const], dtype=int)
        for i in range(0, len(all_cipher_bits_list), N_const)
    ]

    all_decrypted_msg_bits = []
    all_blocks_successfully_decoded = True

    for i, c_block_np in enumerate(cipher_blocks_np_list):
        print(f"Decoding block {i+1}/{num_blocks}...")
        m_block_bits = decode_block_by_error_guessing(c_block_np, G_pub, G_pub_sq_inv, basis_indices)
        
        if m_block_bits is None:
            print(f"Failed to decode block {i+1}.")
            all_blocks_successfully_decoded = False
            break
        all_decrypted_msg_bits.extend(m_block_bits)

    if all_blocks_successfully_decoded:
        print("All blocks decoded. Unpadding message...")
        final_message_bits = unpad_message_bits(all_decrypted_msg_bits)
        
        if final_message_bits is not None:
            print("Converting bits to string...")
            recovered_message = bits_to_string(final_message_bits)
            print("\n🎉 Successfully Decrypted Message: 🎉")
            print(recovered_message)
        else:
            print("Failed to unpad the message.")
    else:
        print("One or more blocks could not be decoded. Full message not recovered.")
