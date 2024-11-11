import os
from paths import folders, extensions

def collect_file_contents(folders, extensions, output_path):
    content = ""
    
    for folder in folders:
        # Expand the path first
        path = os.path.expanduser(folder)
        
        # Handle individual files
        if os.path.isfile(path):
            file_extension = os.path.splitext(path)[1][1:]  # Get the extension without the dot
            if file_extension in extensions:
                print(f"Reading file: {path}")
                try:
                    with open(path, 'r') as f:
                        file_content = f.read()
                        content += f"## {path}\n```\n{file_content}\n```\n\n"
                except Exception as e:
                    print(f"Error reading file {path}: {e}")
            continue
            
        # Handle folders
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_extension = os.path.splitext(file)[1][1:]
                    if file_extension in extensions:
                        file_path = os.path.join(root, file)
                        print(f"Reading file: {file_path}")
                        try:
                            with open(file_path, 'r') as f:
                                file_content = f.read()
                                content += f"## {file_path}\n```\n{file_content}\n```\n\n"
                        except Exception as e:
                            print(f"Error reading file {file_path}: {e}")
        else:
            print(f"Warning: Path not found or accessible: {path}")
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Write the collected content
    try:
        with open(output_path, 'w') as output_file:
            output_file.write(content)
        print(f"Content has been saved to {output_path}")
    except Exception as e:
        print(f"Error writing to output file: {e}")

output_path = "./prompt.md"

collect_file_contents(folders, extensions, output_path)
