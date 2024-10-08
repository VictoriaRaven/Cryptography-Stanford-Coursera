def str_to_int(s):
    return int(s.encode().hex(), 16)


key = str_to_int("attack at dawn") ^ 0x09e1c5f70a65ac519458e7e53f36

print(hex(str_to_int("attack at dusk") ^ key))

# Answer: 09e1c5f70a65ac519458e7f13b33
