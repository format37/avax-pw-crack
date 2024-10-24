import math
import numpy as np
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class PrecisionParams:
    max_a: int
    max_b: int
    desired_precision: float  # in decimal points for multiplication result

class AnglePrecisionAnalyzer:
    """Analyzes required angle precision for trigonometric multiplication."""
    
    @staticmethod
    def angle_function(b: float) -> float:
        """The exact angle calculation function."""
        return math.asin(1 / math.sqrt(1 + b**2))
    
    @staticmethod
    def calculate_derivative(b: float) -> float:
        """Calculate derivative of angle function with respect to b."""
        return -1 / (math.sqrt(1 + b**2) * (b * math.sqrt(1 + b**2)))
    
    @staticmethod
    def calculate_multiplication_error(a: float, b: float, angle_error: float) -> float:
        """Calculate how angle error affects multiplication result."""
        exact_angle = math.asin(1 / math.sqrt(1 + b**2))
        perturbed_angle = exact_angle + angle_error
        
        exact_result = a * b
        perturbed_result = a / math.tan(perturbed_angle)
        
        return abs(exact_result - perturbed_result)
    
    def determine_required_precision(self, params: PrecisionParams) -> dict:
        """
        Determine required angle table parameters for given precision requirements.
        
        The formula derivation:
        1. For multiplication a × b using angle θ:
           result = a / tan(θ)
        
        2. Error in angle (Δθ) causes error in result (ΔR):
           ΔR ≈ a × (d/dθ)[1/tan(θ)] × Δθ
           
        3. Maximum error occurs at maximum 'a' value:
           max_error = max_a × (1/sin²(θ)) × Δθ
           
        4. For logarithmic spacing between angles:
           Δθ ≈ θ'(b) × b × ln(step_ratio)
           where step_ratio is the ratio between consecutive b values
        """
        # Calculate minimum angle (at max_b)
        min_angle = self.angle_function(params.max_b)
        
        # Calculate angle sensitivity at max_b
        angle_sensitivity = 1 / (math.sin(min_angle)**2)
        
        # Calculate required angle precision
        required_angle_precision = params.desired_precision / (params.max_a * angle_sensitivity)
        
        # Calculate optimal number of points using derivative at max_b
        derivative_at_max = abs(self.calculate_derivative(params.max_b))
        step_ratio = math.exp(required_angle_precision / (params.max_b * derivative_at_max))
        
        # Calculate required number of points
        required_points = math.ceil(math.log(params.max_b) / math.log(step_ratio))
        
        # Calculate optimal step size for linear spacing
        optimal_linear_step = (2 * params.desired_precision * min_angle) / (params.max_a * angle_sensitivity)
        
        return {
            'required_angle_precision': required_angle_precision,
            'recommended_points': required_points,
            'min_angle': min_angle,
            'optimal_step_ratio': step_ratio,
            'optimal_linear_step': optimal_linear_step
        }
    
    def verify_precision(self, params: PrecisionParams, num_points: int) -> List[Tuple[float, float]]:
        """Verify precision using given number of points."""
        # Create logarithmically spaced points
        b_values = np.exp(np.linspace(np.log(1), np.log(params.max_b), num_points))
        
        # Test at midpoints between reference points
        test_points = []
        for i in range(len(b_values) - 1):
            mid_b = math.sqrt(b_values[i] * b_values[i + 1])
            
            # Interpolate angle
            lower_angle = self.angle_function(b_values[i])
            ratio = b_values[i] / mid_b
            interpolated_angle = lower_angle * ratio
            
            # Calculate error
            error = self.calculate_multiplication_error(
                params.max_a, mid_b, 
                interpolated_angle - self.angle_function(mid_b)
            )
            
            test_points.append((mid_b, error))
            
        return test_points

def main():
    # Example parameters
    params = PrecisionParams(
        max_a=1000,    # maximum value of a
        max_b=1000,    # maximum value of b
        desired_precision=1.0  # desired precision (1.0 for integer precision)
    )
    
    analyzer = AnglePrecisionAnalyzer()
    results = analyzer.determine_required_precision(params)
    
    print("Angle Table Parameters Formula")
    print("=" * 50)
    print(f"Given:")
    print(f"  max_a = {params.max_a}")
    print(f"  max_b = {params.max_b}")
    print(f"  desired_precision = {params.desired_precision}")
    
    print("\nDerived Parameters:")
    print(f"  Minimum angle: {results['min_angle']:.8f} radians")
    print(f"  Required angle precision: {results['required_angle_precision']:.8e} radians")
    print(f"  Recommended number of points: {results['recommended_points']}")
    print(f"  Optimal step ratio: {results['optimal_step_ratio']:.4f}")
    
    print("\nFormula for Required Points:")
    print("N = ceil( ln(max_b) / ln(1 + precision/(max_a * sensitivity)) )")
    print("where:")
    print("- sensitivity = 1/sin²(arcsin(1/sqrt(1 + max_b²)))")
    print("- precision is desired precision in result")
    
    # Verify precision
    print("\nPrecision Verification:")
    test_points = analyzer.verify_precision(params, results['recommended_points'])
    max_error = max(error for _, error in test_points)
    print(f"Maximum observed error: {max_error:.6f}")
    print(f"Meets precision requirement: {max_error <= params.desired_precision}")

if __name__ == '__main__':
    main()
