import os

def write_file_contents_to_output(directory, output_file):
    with open(output_file, 'w') as output:
        for root, dirs, files in os.walk(directory):
            for file in files:
                # If file have no extension, continue
                if '.' not in file:
                    print(f"Skipping file: {file}")
                    continue
                file_path = os.path.join(root, file)
                print(f"Writing file: {file_path}")
                output.write(f"<<< File: {file_path} >>>\n")
                # If you decide you want file size or modified date, add it here
                try:
                    with open(file_path, 'r') as f:
                        contents = f.read()
                except Exception as e:
                    contents = f"Error reading file: {e}\n"
                output.write(contents + "\n\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
    else:
        directory_path = sys.argv[1]
        # ouptut name is the same as the right directory name
        output_file_path = os.path.basename(directory_path) + ".txt".replace("/", "")
        # Remove file if it exists
        if os.path.exists(output_file_path):
            os.remove(output_file_path)
        write_file_contents_to_output(directory_path, output_file_path)
        print(f"Contents written to {output_file_path}")
