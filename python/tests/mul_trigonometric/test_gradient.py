import math
import numpy as np
from typing import Tuple

class TrigonometricMultiplier:
    def __init__(self, max_reference: int = 120, num_points: int = 12):
        """Initialize with logarithmically spaced reference points."""
        # Create logarithmically spaced points
        self.reference_points = np.unique(np.round(
            np.exp(np.linspace(np.log(1), np.log(max_reference), num_points))
        )).astype(int)
        
        # Calculate exact angles for reference points
        self.reference_angles = {
            b: math.asin(1 / math.sqrt(1 + b**2))
            for b in self.reference_points
        }
    
    def find_nearest_references(self, b: float) -> Tuple[float, float]:
        """Find nearest reference points for given b."""
        # Find the first reference point larger than b
        upper_idx = np.searchsorted(self.reference_points, b)
        if upper_idx == 0:
            return self.reference_points[0], self.reference_points[0]
        if upper_idx == len(self.reference_points):
            return self.reference_points[-1], self.reference_points[-1]
            
        lower_b = self.reference_points[upper_idx - 1]
        upper_b = self.reference_points[upper_idx]
        return lower_b, upper_b
    
    def interpolate_angle_linear(self, b: float) -> float:
        """Basic linear interpolation."""
        lower_b, upper_b = self.find_nearest_references(b)
        lower_angle = self.reference_angles[lower_b]
        upper_angle = self.reference_angles[upper_b]
        
        if upper_b == lower_b:
            return lower_angle
            
        t = (b - lower_b) / (upper_b - lower_b)
        return lower_angle + t * (upper_angle - lower_angle)
    
    def interpolate_angle_trig(self, b: float) -> float:
        """Interpolate using the known shape of arcsin(1/sqrt(1 + x²))."""
        lower_b, upper_b = self.find_nearest_references(b)
        lower_angle = self.reference_angles[lower_b]
        upper_angle = self.reference_angles[upper_b]
        
        if upper_b == lower_b:
            return lower_angle
        
        # Instead of linear interpolation, use the known relationship
        # angle ≈ 1/b for large b
        # This approximates the shape of arcsin(1/sqrt(1 + b²))
        b_ratio = lower_b / b
        return lower_angle * b_ratio
    
    def multiply(self, a: float, b: float, method: str = 'trig') -> Tuple[float, float, float]:
        """Perform multiplication using specified interpolation method."""
        # Get exact angle and result for comparison
        exact_angle = math.asin(1 / math.sqrt(1 + b**2))
        exact_result = a / math.tan(exact_angle)
        
        # Get interpolated angle based on method
        if method == 'linear':
            approx_angle = self.interpolate_angle_linear(b)
        else:
            approx_angle = self.interpolate_angle_trig(b)
            
        approx_result = a / math.tan(approx_angle)
        
        return approx_result, exact_result, abs(approx_result - exact_result)

def analyze_approximation():
    # Initialize multiplier
    multiplier = TrigonometricMultiplier(max_reference=120, num_points=12)
    
    # Print reference points and angles
    print("Reference Points and Angles (logarithmically spaced)")
    print("b : angle (radians)")
    print("-" * 40)
    for b in multiplier.reference_points:
        print(f"{b:3d} : {multiplier.reference_angles[b]:.6f}")
    
    # Test cases
    test_cases = [
        (23, 78),  # Original case
        (15, 45),  # Mid-range values
        (5, 95),   # Small a, large b
        (50, 60),  # Large a, mid b
        (100, 110) # Large values
    ]
    
    # Compare linear vs trigonometric interpolation
    print("\nComparison of Interpolation Methods")
    print("-" * 80)
    
    for a, b in test_cases:
        print(f"\nTest case: {a} × {b}")
        
        # Linear interpolation
        approx_linear, exact, err_linear = multiplier.multiply(a, b, 'linear')
        rel_error_linear = (err_linear / exact) * 100
        
        # Trigonometric interpolation
        approx_trig, exact, err_trig = multiplier.multiply(a, b, 'trig')
        rel_error_trig = (err_trig / exact) * 100
        
        print(f"Linear:        {approx_linear:.6f} = {exact:.6f} ± {err_linear:.6f} ({rel_error_linear:.6f}%)")
        print(f"Trigonometric: {approx_trig:.6f} = {exact:.6f} ± {err_trig:.6f} ({rel_error_trig:.6f}%)")

if __name__ == '__main__':
    analyze_approximation()