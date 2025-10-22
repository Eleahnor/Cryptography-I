from Crypto.Util import number
import os
import random
def generate_prime():
    # 256 512 1014 2048 3072
    prime_256_bits = number.getPrime(256, randfunc=os.urandom)
    print(f"\nPrimo de 256 bits: {prime_256_bits}")
    #print(f"En base 64: {prime_256_bits.to_bytes((prime_256_bits.bit_length() + 7) // 8, 'big').hex()}")
    print(f"Tamaño en bits (aproximado): {prime_256_bits.bit_length()} bits")

    prime_512_bits = number.getPrime(512, randfunc=os.urandom)
    print(f"\nPrimo de 512 bits: {prime_512_bits}")
    print(f"Tamaño en bits (aproximado): {prime_512_bits.bit_length()} bits")

    prime_1024_bits = number.getPrime(1024, randfunc=os.urandom)
    print(f"\nPrimo de 1024 bits: {prime_1024_bits}")
    print(f"Tamaño en bits (aproximado): {prime_1024_bits.bit_length()} bits")

    prime_2048_bits = number.getPrime(2048, randfunc=os.urandom)
    print(f"\nPrimo de 2048 bits: {prime_2048_bits}")
    print(f"Tamaño en bits (aproximado): {prime_2048_bits.bit_length()} bits")

    prime_3072_bits = number.getPrime(3072, randfunc=os.urandom)
    print(f"\nPrimo de 3072 bits: {prime_3072_bits}")
    print(f"Tamaño en bits (aproximado): {prime_3072_bits.bit_length()} bits")

def generate_rsa_key(bit_length):
    if bit_length < 512:
        raise ValueError("La longitud en bits de los números primos debe ser al menos 512.")

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


def is_primitive_root(g, p):
    required_set = set()
    for i in range(1, p):
        required_set.add(pow(g, i, p))
    return len(required_set) == p - 1

def find_primitive_root(p):
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return None

def main():
    while True:
        print("\n Prime Number Generation")
        print("[1] Generate Prime numbers with diferent bit lengths")
        print("[2] Generate RSA key")
        print("[3] Generator/Primitive element of a finite field")
        print("[4] Decrypt exercise 1")
        print("[0] Exit")
        opc = input("Select an option: ")   
        print()

        if opc == '0': 
            print("Exiting the program...")
            break
        elif opc == '1':
            generate_prime()
        
        elif opc == '2':
            bit_length = int(input("Enter the bit length for prime numbers in key generation: "))
            public_key, private_key = generate_rsa_key(bit_length)

            print("\n--- Public key ---")
            print(f"e: {public_key[0]}")
            print(f"n: {public_key[1]}")
            print(f"Length in bits: {public_key[1].bit_length()} bits")

            print("\n--- Secret Key ---")
            print(f"d: {private_key}")
            print(f"Length in bits: {private_key.bit_length()} bits\n")

        elif opc == '3':
            primes = [number.getPrime(15) for _ in range(3)]
            for p in primes:
                g = find_primitive_root(p)
                print(f"Prime p = {p}")
                if g:
                    print(f"Primitive root (generator) g = {g}\n")
                else:
                    print("No primitive root found.\n")

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
