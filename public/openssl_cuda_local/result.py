def print_last_n_lines(filename, lines_count):
    try:
        with open(filename, 'r') as file:
            # Read all lines and store them in a list
            lines = file.readlines()
            
            # Get the last N lines (or all if file has fewer than 10 lines)
            last_n_lines = lines[-lines_count:]
            
            # Print the last n lines
            for line in last_n_lines:
                print(line.strip())
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except IOError:
        print(f"Error: There was an issue reading the file '{filename}'.")

# Call the function with the filename
print_last_n_lines('run.log', 30)
