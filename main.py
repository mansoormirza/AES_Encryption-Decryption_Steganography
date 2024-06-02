from AES_Encryption.aes_encrypt import encrypt
from AES_Encryption.aes_decrypt import decrypt
from Steganography.encoder import encode
from Steganography.decoder import decode

def encrypt_message(message, passphrase):
    if len(passphrase) < 16:
        passphrase = passphrase.ljust(16, '0')
        print(f"Passphrase padded: {passphrase}")
    elif len(passphrase) > 16:
        print("Your passphrase was larger than 16 characters. Truncating passphrase.")
        passphrase = passphrase[:16]

    print('Passphrase is: ',passphrase)
    
    encrypted_text = encrypt(message, passphrase)
    return encrypted_text

def process_cover_image(cover_image_path, encrypted_text):
    encoded_image_path = encode(cover_image_path, encrypted_text)
    return encoded_image_path

def decrypt_message(encrypted_image_path, passphrase):
    extracted_encrypted_text = decode(encrypted_image_path)
    decrypted_text = decrypt(extracted_encrypted_text, passphrase)
    return decrypted_text

def main():
    # Get inputs from the user
    message = input("Enter the message to encrypt: ")
    passphrase = input("Enter a 16-character passphrase: ")
    cover_image_path = input("Enter the path to the cover image: ")

    # Encryption process
    encrypted_text = encrypt_message(message, passphrase)
    print(f"Encrypted Text: {encrypted_text}")
    
    encoded_image_path = process_cover_image(cover_image_path, encrypted_text)
    print(f"Encoded Image Path: {encoded_image_path}")
    
    # Decryption process
    encrypted_image_path = input("Enter the path to the encoded image: ")
    new_passphrase = input("Enter the passphrase for decryption: ")
    
    decrypted_text = decrypt_message(encrypted_image_path, new_passphrase)
    print(f"Decrypted Text: {decrypted_text}")

if __name__ == "__main__":
    main()
