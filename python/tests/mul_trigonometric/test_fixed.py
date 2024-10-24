import math
from collections import OrderedDict

def get_unique_angles():
    """Calculate unique angles for trigonometric multiplication in radians."""
    angles = OrderedDict()  # to maintain order
    
    print("Unique Trigonometric Multiplication Constants")
    print("b : angle (radians), angle (degrees), π representation")
    print("-" * 60)
    
    for b in range(1, 13):
        # Calculate angle in radians
        angle_rad = math.asin(1 / math.sqrt(1 + b**2))
        angle_deg = math.degrees(angle_rad)
        
        # Try to express in terms of π
        pi_ratio = angle_deg / 180.0
        pi_repr = f"{angle_rad:.6f}"  # default representation
        
        # Look for simple π fractions
        for denominator in range(1, 50):
            numerator = round(pi_ratio * denominator)
            if abs(numerator / denominator - pi_ratio) < 1e-10:
                if numerator == 1:
                    pi_repr = f"π/{denominator}"
                else:
                    pi_repr = f"{numerator}π/{denominator}"
                break
        
        print(f"{b:2d} : {angle_rad:.6f} rad, {angle_deg:.6f}°, {pi_repr}")
        angles[b] = angle_rad
    
    return angles

def mul_trigonometric(a, b, angles=None):
    """Multiply using trigonometric approach with precomputed angles."""
    if angles and b in angles:
        angle = angles[b]
    else:
        angle = math.asin(1 / math.sqrt(1 + b**2))
    return a / math.tan(angle)

def main():
    # Get unique angles
    angles = get_unique_angles()
    
    # Test multiplication
    print("\nTesting multiplication:")
    a, b = 4, 3
    product = mul_trigonometric(a, b, angles)
    print(f"{a} × {b} = {product}")
    
    # Verify accuracy for first few multiplications
    print("\nVerification of first few multiplications:")
    for a in range(1, 5):
        for b in range(a, a+3):
            result = mul_trigonometric(a, b, angles)
            error = abs(result - (a * b))
            print(f"{a} × {b} = {result:.10f} (error: {error:.2e})")

if __name__ == '__main__':
    main()