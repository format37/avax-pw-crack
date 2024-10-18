import math

def div_trigonometric(dividend, divisor):
    # quotient = dividend * tan(arctg(1/divisor))
    quotient = dividend * math.tan(math.atan(1 / divisor))
    # Ceil down
    quotient = math.floor(quotient)
    # Get remainder utilizing only subtraction and multiplication
    remainder = dividend - (quotient * divisor)
    return quotient, remainder
    

def main():
    dividend = 13
    divisor = 3
    print("Dividend: ", dividend)
    print("Divisor: ", divisor)
    quotient, remainder = div_trigonometric(dividend, divisor)
    print(f"Quotient: {quotient}")
    print(f"Remainder: {remainder}")

if __name__ == '__main__':
    main()