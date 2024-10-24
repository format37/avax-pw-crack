import math
import numpy as np
from typing import Dict, Tuple

class AngleTableGenerator:
    def __init__(self, max_a: int, max_b: int):
        """Initialize generator with maximum values."""
        self.max_a = max_a
        self.max_b = max_b
        self.angles: Dict[int, float] = {}
        
    def _calculate_required_points(self) -> int:
        """Calculate required number of points for integer precision."""
        min_angle = math.asin(1 / math.sqrt(1 + self.max_b**2))
        sensitivity = 1 / (math.sin(min_angle)**2)
        precision = 1.0  # for integer precision
        
        step_ratio = 1 + precision/(self.max_a * sensitivity)
        return math.ceil(math.log(self.max_b) / math.log(step_ratio))
    
    def generate_table(self) -> Dict[int, float]:
        """Generate optimal angle lookup table."""
        n_points = self._calculate_required_points()
        
        # Generate logarithmically spaced points
        b_values = np.unique(np.round(
            np.exp(np.linspace(np.log(1), np.log(self.max_b), n_points))
        )).astype(int)
        
        # Calculate angles for each point
        self.angles = {
            int(b): math.asin(1 / math.sqrt(1 + b**2))
            for b in b_values
        }
        
        return self.angles
    
    def multiply(self, a: int, b: int) -> int:
        """Perform multiplication using the angle table."""
        if not self.angles:
            self.generate_table()
            
        if b in self.angles:
            angle = self.angles[b]
        else:
            # Find nearest lower reference point
            lower_b = max(key for key in self.angles.keys() if key <= b)
            lower_angle = self.angles[lower_b]
            # Apply trigonometric approximation
            angle = lower_angle * (lower_b / b)
            
        result = a / math.tan(angle)
        return round(result)  # Round to nearest integer

def verify_precision(generator: AngleTableGenerator, test_cases: int = 100) -> Tuple[float, float]:
    """Verify precision of the multiplication."""
    max_error = 0
    avg_error = 0
    
    # Generate random test cases
    np.random.seed(42)  # for reproducibility
    test_a = np.random.randint(1, generator.max_a + 1, test_cases)
    test_b = np.random.randint(1, generator.max_b + 1, test_cases)
    
    for a, b in zip(test_a, test_b):
        exact = a * b
        approx = generator.multiply(a, b)
        error = abs(exact - approx)
        max_error = max(max_error, error)
        avg_error += error
        
    avg_error /= test_cases
    return max_error, avg_error

def main():
    # Example usage
    max_a = 1000
    max_b = 1000
    
    generator = AngleTableGenerator(max_a, max_b)
    angles = generator.generate_table()
    
    print(f"Generated angle table with {len(angles)} points")
    print("\nSample points:")
    print("b : angle (radians)")
    print("-" * 30)
    for b in list(angles.keys())[:10]:  # First 10 points
        print(f"{b:4d} : {angles[b]:.8f}")
    print("...")
    
    # Verify precision
    max_error, avg_error = verify_precision(generator)
    print(f"\nPrecision verification (100 random test cases):")
    print(f"Maximum error: {max_error}")
    print(f"Average error: {avg_error:.6f}")
    
    # Example multiplications
    test_cases = [(5, 7), (12, 23), (45, 67), (123, 456), (999, 999)]
    print("\nExample multiplications:")
    for a, b in test_cases:
        result = generator.multiply(a, b)
        exact = a * b
        error = abs(result - exact)
        print(f"{a:3d} × {b:3d} = {result:6d} (exact: {exact:6d}, error: {error})")

if __name__ == '__main__':
    main()
