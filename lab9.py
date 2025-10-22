import math
import os
from Crypto.Util import number

def find_p_q(n):
    """
    Encuentra los factores primos p y q de un número n.
    Esta es una implementación simple y solo funciona para números pequeños.
    """
    lim = math.floor(n**0.5)

    for i in range(3, lim + 1, 2):
        if n % i == 0:
            p = i
            q = n // i
            return p, q
    return None

def exponenciacion_modular(a, e, n):
    """
    Calcula (a^e) mod n de manera eficiente.
    """
    res = 1
    a = a % n  # Reducir base al módulo
    
    while e > 0:
        if e % 2 == 1:
            res = (res * a) % n
        e = e // 2
        a = (a * a) % n
    
    return res

# Función de Cifrado RSA
def rsa_encrypt(m, public_key):
    """
    Cifra un mensaje m usando la clave pública (e, n).
    """
    e, n = public_key
    if not (1 < m < n):
        raise ValueError(f"El mensaje m debe satisfacer 1 < m < {n}, se obtuvo m = {m}")
    c = exponenciacion_modular(m, e, n)
    return c

# Función de Descifrado RSA
def rsa_decrypt(c, private_key, n):
    """
    Descifra un texto cifrado c usando la clave privada d y el módulo n.
    """
    d = private_key
    m = exponenciacion_modular(c, d, n)
    return m

# Función de Generación de Claves RSA
def generate_rsa_key(bit_length):
    """
    Genera un par de claves RSA (pública y privada).
    """
    print(f"Generando par de claves RSA con primos de {bit_length} bits cada uno...")
    p = number.getPrime(bit_length, randfunc=os.urandom)
    q = number.getPrime(bit_length, randfunc=os.urandom)

    while p == q:
        q = number.getPrime(bit_length, randfunc=os.urandom)

    n = p * q
    phi = (p - 1) * (q - 1)
    
    while True:
        e = number.getPrime(17, randfunc=os.urandom)
        if number.GCD(e, phi) == 1:
            break

    d = number.inverse(e, phi)

    public_key = (e, n)
    private_key = d

    return public_key, private_key

def main():
    while True:
        print("\nLab 9 - Ejercicios") 
        print("[1] Encontrar m y la comprobación")
        print("[2] Exponenciación modular")
        print("[3] Generar clave RSA aleatoria")
        print("[4] Cifrado RSA")
        print("[5] Descifrado RSA")
        print("[0] Salir")
        option = input("Selecciona una opción: ")

        if option == '0':
            print("Saliendo...")
            break

        elif option == '1':
            n = int(input("Ingresa n: "))
            e = int(input("Ingresa e: "))
            c = int(input("Ingresa c: "))

            p, q = find_p_q(n)
            phi = (p - 1) * (q - 1)
            d = pow(e, -1, phi)

            m = pow(c, d, n)
            print(f"m: {m}")
            print(f"p: {p}, q: {q}")
            print(f"Comprobación: {pow(m, e, n) == c}")
        
        elif option == '2':
            a = int(input("Ingresa la base (a): "))
            e = int(input("Ingresa el exponente (e): "))
            n = int(input("Ingresa el módulo (n): "))

            result = exponenciacion_modular(a, e, n)
            print(f"El resultado de {a}^{e} mod {n} es: {result}")
        
        elif option == '3':
            public_key, private_key = generate_rsa_key(64)

            print("\n--- Clave Pública ---")
            print(f"e: {public_key[0]}")
            print(f"n: {public_key[1]}")
            print(f"Longitud en bits: {public_key[1].bit_length()} bits")

            print("\n--- Clave Secreta ---")
            print(f"d: {private_key}")
            print(f"Longitud en bits: {private_key.bit_length()} bits\n")
        
        elif option == '4':
            try:
                e = int(input("Ingresa el exponente público (e): "))
                n = int(input("Ingresa el módulo (n): "))
                # Pedir la entrada como una cadena hexadecimal
                m = input("Ingresa el mensaje (m) en formato hexadecimal: ")
                
                # Convertir el mensaje de hexadecimal a entero
                #m = int(m_hex, 16)

                public_key = (e, n)
                c = rsa_encrypt(m, public_key)
                
                # Mostrar el resultado en decimal y hexadecimal
                print(f"\n--- Resultado del Cifrado ---")
                print(f"Texto cifrado c (decimal): {c}")
                print(f"Texto cifrado c (hexadecimal): {hex(c)}")
                
            except ValueError as err:
                print(f"Error: Entrada inválida. Asegúrate de que los números y el formato hexadecimal son correctos. ({err})")
        
        elif option == '5':
            try:
                # Pedir la entrada como una cadena hexadecimal
                c = input("Ingresa el texto cifrado (c) en formato hexadecimal: ")
                d = int(input("Ingresa la clave privada (d): "))
                n = int(input("Ingresa el módulo (n): "))
                
                # Convertir el texto cifrado de hexadecimal a entero
                #c = int(c_hex, 16)
                
                m = rsa_decrypt(c, d, n)

                # Mostrar el resultado en decimal y hexadecimal
                print(f"\n--- Resultado del Descifrado ---")
                print(f"Mensaje descifrado m (decimal): {m}")
                print(f"Mensaje descifrado m (hexadecimal): {hex(m)}")

            except ValueError as err:
                print(f"Error: Entrada inválida. Asegúrate de que los números y el formato hexadecimal son correctos. ({err})")
        
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()
