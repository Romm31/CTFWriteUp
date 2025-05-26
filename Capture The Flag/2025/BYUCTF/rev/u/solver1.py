# Decoding the original script
def decode_script():
    # These are the Thai characters used as variable names
    # Mapping them to their actual meanings based on the code
    chr_func = chr
    ord_func = ord
    abs_func = abs
    input_func = input
    all_func = all
    print_func = print
    len_func = len
    pow_func = pow
    range_func = range
    list_func = list
    dict_func = dict
    set_func = set
    
    # The encoded numbers (originally 'รน')
    encoded_numbers = [12838, 1089, 16029, 13761, 1276, 14790, 2091, 17199, 
                       2223, 2925, 17901, 3159, 18135, 18837, 3135, 19071, 
                       4095, 19773, 4797, 4085, 20007, 5733, 20709, 17005, 
                       2601, 9620, 3192, 9724, 3127, 8125]
    
    u = 3
    U = 256
    
    # Get user input (originally 'แนท=รผ()')
    user_input = input_func()
    
    # Create the comparison string (originally 'ส')
    # This is equivalent to: list(pow(u, x, U) for x in range(U))[3:len(encoded_numbers)+3]
    comparison_str = [pow_func(u, x, U) for x in range_func(U)][u:len_func(encoded_numbers)+u]
    
    # Convert user input to list of ordinals
    user_input_ords = [ord_func(c) for c in user_input]
    
    # Verify lengths match
    assert len_func(encoded_numbers) == len_func(user_input_ords)
    
    # Verify each character matches the condition: c * comparison_str[i] == encoded_numbers[i]
    assert all_func([c * x == y for c, x, y in zip(user_input_ords, comparison_str, encoded_numbers)])
    
    print_func("Flag is correct!")

def solve_challenge():
    # To solve, we need to find the input that when multiplied by comparison_str[i] gives encoded_numbers[i]
    encoded_numbers = [12838, 1089, 16029, 13761, 1276, 14790, 2091, 17199, 
                       2223, 2925, 17901, 3159, 18135, 18837, 3135, 19071, 
                       4095, 19773, 4797, 4085, 20007, 5733, 20709, 17005, 
                       2601, 9620, 3192, 9724, 3127, 8125]
    
    u = 3
    U = 256
    
    # Generate the comparison string (same as in the original code)
    comparison_str = [pow(u, x, U) for x in range(U)][3:len(encoded_numbers)+3]
    
    # Calculate each character of the flag: flag_char = encoded_num // comparison_val
    flag_chars = []
    for num, comp in zip(encoded_numbers, comparison_str):
        flag_char = num // comp
        flag_chars.append(chr(flag_char))
    
    flag = ''.join(flag_chars)
    return flag

# Get the flag
flag = solve_challenge()
print("The flag is:", flag)
