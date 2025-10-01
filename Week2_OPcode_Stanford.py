from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import unpad
import binascii

# CBC ciphertext
def decrypt_cbc(key_hex, ciphertext_hex):

    # handles errors with try/except
    if not key_hex or not ciphertext_hex:
        return None
    try:
        # key/ciphertext conversion from hex to bytes
        key = binascii.unhexlify(key_hex)
        ciphertext = binascii.unhexlify(ciphertext_hex)
        
        # find IV of first 16 bytes ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        # make AES cipher to CBC mode with IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # decrypt ciphertext
        decrypted_data = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
        return decrypted_data.decode('utf-8')
    except (ValueError, binascii.Error):
        # Other Errors
        return ""

# CTR ciphertext
def decrypt_ctr(key_hex, ciphertext_hex):
    if not key_hex or not ciphertext_hex:
        return None
    try:
        key = binascii.unhexlify(key_hex)
        ciphertext = binascii.unhexlify(ciphertext_hex)

        # find first 16 bytes
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]

        # IV convert to int for counter
        iv_int = int.from_bytes(iv, byteorder='big')

        # counter obj begin with IV
        ctr = Counter.new(128, initial_value=iv_int)

        # AES decrypt CTR
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        decrypted_data = cipher.decrypt(actual_ciphertext)
        return decrypted_data.decode('utf-8')
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return ""


# ALL CBC keys and ciphertexts given
# 1)
key_hex = "140b41b22a29beb4061bda66b6747e14"
ciphertext_hex = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
# 2)
key_hex2 = "140b41b22a29beb4061bda66b6747e14"
ciphertext_hex2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
# 3)
key_hex3 = "36f18357be4dbd77f050515c73fcf9f2"
ciphertext_hex3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
# 4)
key_hex4 = "36f18357be4dbd77f050515c73fcf9f2"
ciphertext_hex4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

# ALL decrypts ciphertexts
# 1) CBC
plaintext = decrypt_cbc(key_hex, ciphertext_hex)
print("Decrypted plaintext 1:\n", plaintext)
# 2) CBC
plaintext = decrypt_cbc(key_hex2, ciphertext_hex2)
print("Decrypted plaintext 2:\n", plaintext)
#-------------------
# 3) CTR
plaintext = decrypt_ctr(key_hex3, ciphertext_hex3)
print("Decrypted plaintext 3:\n", plaintext)
# 4) CTR
plaintext = decrypt_ctr(key_hex4, ciphertext_hex4)
print("Decrypted plaintext 4:\n", plaintext)

