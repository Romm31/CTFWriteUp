import re

with open("free_flags.txt", "r") as f:
    content = f.read()

flags = re.findall(r"flag\{[^\}]+\}", content)

def is_valid_hex_flag(flag):
    inner = flag[5:-1]
    return bool(re.fullmatch(r"[0-9a-f]{32}", inner))

valid_flags = [flag for flag in flags if is_valid_hex_flag(flag)]
print(valid_flags)
