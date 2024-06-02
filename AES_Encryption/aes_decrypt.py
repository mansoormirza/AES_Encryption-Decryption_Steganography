import sys
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

def decrypt(encrypted_data, key):
    try:
        encrypted_data = b64decode(encrypted_data.encode('utf-8'))
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        derived_key = scrypt(key, salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    except ValueError:
        print("wrong key")
        sys.exit(1)
    except Exception as e:
        return f"Decryption error: {e}"

# Example usage:
# encrypted_data = "..."  # Your encrypted data here
# key = "..."  # Your decryption key here
# result = decrypt(encrypted_data, key)
# print(result)
