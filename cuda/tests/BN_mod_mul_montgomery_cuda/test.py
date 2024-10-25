# Test Case 2 values
a = 0xFFFFFFFFFFFFFFFF
b = 0xFFFFFFFFFFFFFFFF
N = 0xFFFFFFFFFFFFFFFD

# Correct Montgomery Multiplication using Python's built-in capabilities
def montgomery_mul(a, b, N):
    result = (a * b) % N  # Direct calculation
    print(f"Final result: {hex(result)}")
    return result

result = montgomery_mul(a, b, N)