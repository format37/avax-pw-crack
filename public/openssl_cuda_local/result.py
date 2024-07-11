def print_last_10_lines(filename):
    try:
        with open(filename, 'r') as file:
            # Read all lines and store them in a list
            lines = file.readlines()
            
            # Get the last 10 lines (or all if file has fewer than 10 lines)
            last_10_lines = lines[-10:]
            
            # Print the last 10 lines
            for line in last_10_lines:
                print(line.strip())
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except IOError:
        print(f"Error: There was an issue reading the file '{filename}'.")

# Call the function with the filename
print_last_10_lines('run.log')
