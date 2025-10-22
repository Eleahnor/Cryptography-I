from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from bitarray import bitarray

# Generate a random 3DES key (24 bytes for 3-key 3DES)
def rand_key():
    while True:
        key = get_random_bytes(24)
        try:
            DES3.adjust_key_parity(key)
            break
        except ValueError:
            continue
    
    key_base64 = base64.b64encode(key).decode('utf-8')
    print(f"Llave 3DES aleatoria generada (base64): {key_base64}")
    return key_base64

# Encrypt file with 3DES CBC
def Efile(key_base64, input_filename):
    try:
        if not os.path.exists(input_filename):
            raise FileNotFoundError(f"El archivo {input_filename} no existe")

        key = base64.b64decode(key_base64)
        if len(key) != 24:
            raise ValueError("La llave debe ser de 24 bytes para 3DES")

        # Read the plaintext
        with open(input_filename, 'rb') as f:
            plaintext = f.read()

        # Generate random IV
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Pad and encrypt
        padded_text = pad(plaintext, DES3.block_size)
        ciphertext = cipher.encrypt(padded_text)
        
        # Combine IV and ciphertext
        iv_ciphertext = iv + ciphertext
        ciphertext_base64 = base64.b64encode(iv_ciphertext).decode('utf-8')
        
        # Get file name and extension
        base_name, ext = os.path.splitext(input_filename)
        output_filename = f"{base_name}$encrypted{ext}"
        
        with open(output_filename, 'w') as f:
            f.write(ciphertext_base64)
        
        # Remove original file
        os.remove(input_filename)
        
        print(f"Archivo cifrado guardado como: {output_filename}")
        print(f"Archivo original {input_filename} eliminado")
        return output_filename

    except Exception as e:
        print(f"Error al cifrar: {str(e)}")
        return None

# Decrypt file with 3DES CBC
def Dfile(key_base64, encrypted_filename):
    try:
        if not os.path.exists(encrypted_filename):
            raise FileNotFoundError(f"El archivo {encrypted_filename} no existe")

        key = base64.b64decode(key_base64)
        if len(key) != 24:
            raise ValueError("La llave debe ser de 24 bytes para 3DES")

        with open(encrypted_filename, 'r') as f:
            ciphertext_base64 = f.read()

        iv_ciphertext = base64.b64decode(ciphertext_base64)
        iv = iv_ciphertext[:8]
        ciphertext = iv_ciphertext[8:]
        
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, DES3.block_size)

        # Get original filename by removing $encrypted
        output_filename = encrypted_filename.replace('$encrypted', '')
        
        with open(output_filename, 'wb') as f:
            f.write(plaintext)
        
        os.remove(encrypted_filename)
        
        print(f"Archivo descifrado guardado como: {output_filename}")
        return output_filename

    except Exception as e:
        print(f"Error al descifrar: {str(e)}")
        return None

def main():
    while True:
        print("\n* * * 3DES CBC * * *")
        print("[1] Generar llave aleatoria.")
        print("[2] Generar llave desde texto/numero.")
        print("[3] 3DES encrypt (Archivo a encriptar).")
        print("[4] 3DES decrypt (Archivo a desencriptar).")
        print("[0] Salir")
        opc = input("Selecciona una opcion: ")
        print()

        if opc == '0':
            print("Saliendo del programa...")
            break

        elif opc == '1':
            rand_key()

        elif opc == '2':
            key = input("Ingresa la llave en base64: ")
            input_filename = input("Ingresa el nombre del archivo a encriptar: ")
            Efile(key, input_filename)

        elif opc == '3':
            key = input("Ingresa la llave en base64: ")
            encrypted_filename = input("Ingresa el nombre del archivo a desencriptar: ")
            Dfile(key, encrypted_filename)

        else:
            print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()