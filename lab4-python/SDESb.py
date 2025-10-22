import base64
from bitarray import bitarray

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # Permutación para generar subllaves
P4 = [2, 4, 3, 1]  # Permutación P4
IP = [2, 6, 3, 1, 4, 8, 5, 7]  # Permutación inicial
INV_IP = [4, 1, 3, 5, 7, 2, 8, 6]  # Inversa de IP
EP = [4, 1, 2, 3, 2, 3, 4, 1]  # Expansión/Permutación

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


last_key = None
last_k1 = None
last_k2 = None

def isbin(s):
    return all(bit in '01' for bit in s)

def in_to_bin(k_input):
    if isbin(k_input) and len(k_input) == 10:
        return bitarray(k_input)
    
    elif isbin(k_input) and len(k_input) > 10:
        return bitarray(k_input[:10])
    
    # Relleno a la derecha
    elif isbin(k_input):
        return bitarray(k_input + '0' * (10 - len(k_input)))
    
    # Número o texto
    try:
        input_int = int(k_input)
    except ValueError:
        input_int = ord(k_input[0]) if k_input else 0
    
    input_int = input_int & 0x3FF  # Máscara para 10 bits
    binary_key = format(input_int, '010b')
    return bitarray(binary_key)

def permute(bits, permutation):
    result = bitarray(len(permutation))
    for i in range(len(permutation)):
        result[i] = bits[permutation[i] - 1]  # -1 porque las permutaciones están indexadas desde 1
    return result

def circular_shift(bits, shift):
    left, right = bits[:5], bits[5:]
    left = left[shift:] + left[:shift]
    right = right[shift:] + right[:shift]
    return left + right

def generate_subkeys(binary_key):
    print(f"🗝️Key: {binary_key.to01()}")
    
    # Paso 1: aplica p10
    p10_key = permute(binary_key, P10)
    
    # Paso 2: corrimiento circular de 1 bit
    ci_1 = circular_shift(p10_key, 1)
    
    # Paso 3: Aplicamos P8 al corrimiento circular (CI_1) para obtener k1
    k1 = permute(ci_1, P8)
    print(f"🗝️K1 : {k1.to01()}")
    
    # Paso 4: Aplicamos un corrimiento circular de 2 bits a CI_1
    ci_2 = circular_shift(ci_1, 2)
    
    # Paso 5: Aplicamos P8 al corrimiento circular (CI_2) para obtener k2
    k2 = permute(ci_2, P8)
    print(f"🗝️K2 : {k2.to01()}\n")
    
    return k1, k2

def expansion_permutation(bits):
    return permute(bits, EP)

def apply_sboxes(bits):
    left, right = bits[:4], bits[4:]
    
    # Para S0 primero y ultimo
    row_s0 = int(left[0:2].to01(), 2)
    col_s0 = int(left[2:4].to01(), 2)
    s0_val = S0[row_s0][col_s0]
    s0_out = format(s0_val, '02b')
    
    # Para S1 enmedio
    row_s1 = int(right[0:2].to01(), 2)
    col_s1 = int(right[2:4].to01(), 2)
    s1_val = S1[row_s1][col_s1]
    s1_out = format(s1_val, '02b')
    
    return bitarray(s0_out + s1_out)

def function_f(bits, subkey):
    expanded = expansion_permutation(bits)
    xor_result = expanded ^ subkey
    sbox_result = apply_sboxes(xor_result)
    p4_result = permute(sbox_result, P4)
    return p4_result

def ENCRYPT_SDES(binary_str, k1, k2):
    if len(binary_str) != 8 or not all(bit in '01' for bit in binary_str):
        raise ValueError("La cadena debe ser de 8 bits y contener solo 0s y 1s.")
    
    bits = permute(bitarray(binary_str), IP)
    left, right = bits[:4], bits[4:]
    
    f_result = function_f(right, k1)
    nleft = left ^ f_result
    nright = right
    left, right = nright, nleft
    
    f_result = function_f(right, k2)
    nleft = left ^ f_result
    nright = right
    left, right = nright, nleft
    
    final_bits = permute(nleft + nright, INV_IP)
    return final_bits.to01()

def DECRYPT(binary_str, k1, k2):
    if len(binary_str) != 8 or not all(bit in '01' for bit in binary_str):
        raise ValueError("La cadena debe ser de 8 bits y contener solo 0s y 1s.")
    
    bits = permute(bitarray(binary_str), IP)
    left, right = bits[:4], bits[4:]
    
    f_result = function_f(right, k2)
    nleft = left ^ f_result
    nright = right
    left, right = nright, nleft
    
    f_result = function_f(right, k1)
    nleft = left ^ f_result
    nright = right
    
    final_bits = permute(nleft + nright, INV_IP)
    return final_bits.to01()

def text_to_bin(text):
    binary = ''
    for char in text:
        binary += format(ord(char), '08b')
    return binary

def bin_to_text(binary):
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:  
            char_code = int(byte, 2)
            text += chr(char_code)
    return text

def p_int(input_str):
    if isbin(input_str):
        if len(input_str) % 8 != 0: 
            input_str += '0' * (8 - (len(input_str) % 8))
        return input_str
    else:
        return text_to_bin(input_str)

def encrypt_text(input_str, k1, k2):
    binary = p_int(input_str)
    print(f"Entrada en binario: {binary}")
    
    ciphertext = ''
    for i in range(0, len(binary), 8):
        block = binary[i:i+8]
        encrypted_block = ENCRYPT_SDES(block, k1, k2)
        ciphertext += encrypted_block
    
    return ciphertext

def decrypt_text(ciphertext, k1, k2):
    if len(ciphertext) % 8 != 0:
        raise ValueError("El texto cifrado debe tener una longitud múltiplo de 8 bits.")
    
    plaintext_binary = ''
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        decrypted_block = DECRYPT(block, k1, k2)
        plaintext_binary += decrypted_block
    
    plaintext = bin_to_text(plaintext_binary)
    return plaintext, plaintext_binary

#base 64_______________________________________________________________________________
def binary_to_base64(binary_str):
    binary_int = int(binary_str, 2)
    binary_bytes = binary_int.to_bytes((len(binary_str) + 7) // 8, byteorder='big')
    base64_str = base64.b64encode(binary_bytes).decode('utf-8')
    return base64_str

def base64_to_binary(base64_str):
    try:
        binary_bytes = base64.b64decode(base64_str)
        binary_int = int.from_bytes(binary_bytes, byteorder='big')
        binary_str = format(binary_int, 'b').zfill(len(binary_bytes) * 8)
        return binary_str
    except Exception as e:
        print(f"Error al decodificar base64: {e}")
        return None

def main():
    global last_key, last_k1, last_k2
    
    while True:
        print("\n* * * S-DES * * *")
        print("[1] Generar llaves de ronda o subllaves.")
        print("[2] S-DES encrypt (texto o binario).")
        print("[3] S-DES decrypt (texto).")
        print("[4] Base64 encode.")
        print("[5] Base64 decode.")
        print("[0] Salir")
        opc = input("Selecciona una opción: ")
        print()

        if opc == '0':
            print("Saliendo del programa...")
            break
        
        elif opc == '1':
            bitarry = input("Ingresa un valor para la llave (número, texto o binario de 10 bits): ")
            binary_key = in_to_bin(bitarry)
            k1, k2 = generate_subkeys(binary_key)
            last_key = binary_key
            last_k1 = k1
            last_k2 = k2
        
        elif opc == '2':
            if last_key is None:
                print("Error: Primero genera las subllaves (opción 1).")
                continue
            
            text_input = input("Ingresa el texto o cadena binaria para cifrar: ")
            try:
                ciphertext = encrypt_text(text_input, last_k1, last_k2)
                print(f"Texto cifrado (binario): {ciphertext}")
                ciphertext_base64 = binary_to_base64(ciphertext)
                print(f"Texto cifrado (base64): {ciphertext_base64}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif opc == '3':
            if last_key is None:
                print("Error: Primero genera las subllaves (opción 1).")
                continue
            
            ciphertext_input = input("Ingresa el texto cifrado en base64: ")
            ciphertext_binary = base64_to_binary(ciphertext_input)
            if ciphertext_binary is None:
                print("Error: No se pudo decodificar la cadena base64.")
                continue
            
            try:
                plaintext, plaintext_binary = decrypt_text(ciphertext_binary, last_k1, last_k2)
                print(f"Texto descifrado (binario): {plaintext_binary}")
                print(f"Texto descifrado: {plaintext}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif opc == '4':
            binary_input = input("Ingresa una cadena binaria para codificar a base64 (solo 0s y 1s): ")
            if not all(bit in '01' for bit in binary_input):
                print("Error: La cadena debe contener solo 0s y 1s.")
                continue
            base64_str = binary_to_base64(binary_input)
            print(f"Codificado en base64: {base64_str}")
        
        elif opc == '5':
            base64_input = input("Ingresa una cadena en base64 para decodificar: ")
            binary_str = base64_to_binary(base64_input)
            if binary_str is None:
                print("Error: No se pudo decodificar la cadena base64.")
            else:
                print(f"Decodificado a binario: {binary_str}")
        
        else:
            print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()