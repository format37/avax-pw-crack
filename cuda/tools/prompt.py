import os

def collect_file_contents(folders, extensions, output_path):
    content = ""
    
    for folder in folders:
        # if folder is a file
        if os.path.isfile(folder):
            file_path = os.path.expanduser(folder)
            with open(file_path, 'r') as f:
                file_content = f.read()
                content += f"## {file_path}\n```\n{file_content}\n```\n\n"
            continue
        folder_path = os.path.expanduser(folder)
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_extension = os.path.splitext(file)[1][1:]  # Get the extension without the dot
                if file_extension in extensions:
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        file_content = f.read()
                        content += f"## {file_path}\n```\n{file_content}\n```\n\n"
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as output_file:
        output_file.write(content)
    
    print(f"Content has been saved to {output_path}")

# Example usage
extensions = ['cu', 'h', 'c', 'py']
folders = [
    # "~/projects/temp/cuda-fixnum/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-add/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-sub/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-mul/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-div/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-divmod/"
    "../include/",
    "../main.cu",
    ]
output_path = "./prompt.md"

collect_file_contents(folders, extensions, output_path)