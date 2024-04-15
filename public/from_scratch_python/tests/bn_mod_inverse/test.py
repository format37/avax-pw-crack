def modular_inverse(a, n):
    try:
        return pow(a, -1, n)
    except ValueError:
        return None  # No modular inverse if a and n are not coprime

def main():
    print("++ Starting BN_mod_inverse test ++")
    
    test_values_a = [
        0x3,  # Corresponds to '3' in hexadecimal
    ]
    test_values_n = [
        0xB,  # Corresponds to 'B' in hexadecimal, which is '11' in decimal
    ]
    
    num_tests = len(test_values_a)
    
    for i in range(num_tests):
        print(f"Test {i}:")
        a = test_values_a[i]
        n = test_values_n[i]
        
        print(f"a: {a}")
        print(f"n: {n}")
        
        mod_inverse = modular_inverse(a, n)
        
        if mod_inverse is None:
            print("No modular inverse exists for the given 'a' and 'n'.")
        else:
            print(f"modular inverse: {mod_inverse}")

if __name__ == "__main__":
    main()

