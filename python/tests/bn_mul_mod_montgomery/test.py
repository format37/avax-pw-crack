def montgomery_multiplication(a, b, n):
    """
    Perform Montgomery multiplication of a and b modulo n.
    
    Parameters:
    a (int): First operand.
    b (int): Second operand.
    n (int): Modulus.

    Returns:
    int: The result of (a * b) mod n using Montgomery multiplication.
    """
    import math
    DEBUG_PRINT = False

    def print_hex(label, value):
        """Print a value in hex format with a label"""
        print(f"{label}: {hex(value)[2:].upper()}")

    print("\nTest inputs:")
    print_hex("a", a)
    print_hex("b", b)
    print_hex("n", n)

    # Step 1: Calculate R = 2^k where k is the number of bits in n
    k = n.bit_length()
    R = 1 << k  # R = 2^k

    if DEBUG_PRINT:
        print("\nR calculation:")
        print(f"k (bits in n): {k}")
        print_hex("R", R)

    # Ensure R and n are coprime
    assert math.gcd(R, n) == 1, "R and n must be coprime."

    # Step 2: Compute n' = -n^{-1} mod R
    n_inv = pow(-n, -1, R)
    n_prime = n_inv % R

    if DEBUG_PRINT:
        print("\nMontgomery values:")
        print_hex("n'", n_prime)

    # Step 3: Convert operands to Montgomery form
    a_bar = (a * R) % n
    b_bar = (b * R) % n

    if DEBUG_PRINT:
        print("\nMontgomery form (RR values):")
        print_hex("aRR", a_bar)
        print_hex("bRR", b_bar)

    if DEBUG_PRINT:
        # Step 4: Montgomery multiplication in Montgomery form
        print("\nMontgomery multiplication steps:")
    t = a_bar * b_bar
    if DEBUG_PRINT:
        print_hex("t = aRR * bRR", t)
    
    m = (t * n_prime) % R
    if DEBUG_PRINT:
        print_hex("m = (t * n') mod R", m)
    
    u = (t + m * n) // R
    if u >= n:
        u -= n
    if DEBUG_PRINT:
        print_hex("u (first reduction)", u)

        # Step 5: Convert result back from Montgomery form
        print("\nConversion from Montgomery form:")
    t = u
    if DEBUG_PRINT:
        print_hex("t", t)
    
    m = (t * n_prime) % R
    if DEBUG_PRINT:
        print_hex("m = (t * n') mod R", m)
    
    u = (t + m * n) // R
    if u >= n:
        u -= n
    if DEBUG_PRINT:
        print_hex("u (final result)", u)

    return u

def test_montgomery_multiplication():
    """
    Test cases for Montgomery multiplication implementation.
    Each test case includes:
    - a, b: operands
    - n: modulus
    - description: explanation of what the test case verifies
    """
    test_cases = [
        # Test Case 1: Basic small numbers (original example)
        {
            'a': 45,    # 0x2D
            'b': 76,    # 0x4C
            'n': 101,   # 0x65
            'description': 'Basic case with small numbers'
        },
        
        # Test Case 2: Powers of 2
        {
            'a': 64,    # 2^6
            'b': 32,    # 2^5
            'n': 97,    # Prime close to power of 2
            'description': 'Powers of 2 as operands'
        },
        
        # Test Case 3: Large prime modulus
        {
            'a': 0xFFF1,
            'b': 0xFFF2,
            'n': 0xFFF7,  # Large prime number
            'description': 'Large prime modulus with values close to modulus'
        },
        
        # Test Case 4: Edge case - operands equal to modulus minus 1
        {
            'a': 96,    # n-1
            'b': 96,    # n-1
            'n': 97,    # Prime modulus
            'description': 'Both operands are n-1'
        },
        
        # Test Case 5: Edge case - one operand is 1
        {
            'a': 1,
            'b': 0xFF,
            'n': 251,   # Prime
            'description': 'Multiplication by 1'
        },
        
        # Test Case 6: Edge case - one operand is 0
        {
            'a': 0,
            'b': 0xFF,
            'n': 251,
            'description': 'Multiplication by 0'
        },
        
        # Test Case 7: Operands larger than modulus
        {
            'a': 301,   # > n
            'b': 401,   # > n
            'n': 251,
            'description': 'Both operands larger than modulus'
        },
        
        # Test Case 8: Modulus with specific bit pattern
        {
            'a': 0xAAAA,  # 1010...1010
            'b': 0x5555,  # 0101...0101
            'n': 0xFFFB,  # Prime close to power of 2
            'description': 'Alternating bit patterns'
        },
        
        # Test Case 9: Equal operands
        {
            'a': 0x1234,
            'b': 0x1234,
            'n': 0xFFFD,  # Prime
            'description': 'Square calculation (a × a mod n)'
        },
        
        # Test Case 10: Operations with small prime modulus
        {
            'a': 15,
            'b': 13,
            'n': 17,    # Small prime
            'description': 'Small prime modulus'
        }
    ]
    
    # Run all test cases
    for i, test in enumerate(test_cases, 1):
        print(f"\n=== Test Case {i}: {test['description']} ===")
        result = montgomery_multiplication(test['a'], test['b'], test['n'])
        expected = (test['a'] * test['b']) % test['n']
        
        print(f"Expected: {expected} (0x{expected:X})")
        print(f"Result:   {result} (0x{result:X})")
        print(f"{'✓ PASS' if result == expected else '✗ FAIL'}")
        # break # TODO: Remove this line to run all test cases

if __name__ == "__main__":
    # Set DEBUG_PRINT to True to see detailed steps
    DEBUG_PRINT = False
    test_montgomery_multiplication()