import os

# Define the paths
include_folder = "/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/"
main_cu_path = "/home/alex/projects/avax-pw-crack/cuda_implementation/main.cu"
# main_cu_path = "/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/tests/bn_add_128/test.cu"
output_path = "/home/alex/Documents/prompts/prompt.md"

# Initialize the content variable
content = ""

# Iterate through files in the include folder
for filename in os.listdir(include_folder):
    file_path = os.path.join(include_folder, filename)
    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            file_content = file.read()
            content += f"# {filename}\n```\n{file_content}\n```\n\n"

# Add content of main.cu
with open(main_cu_path, 'r') as main_cu_file:
    main_cu_content = main_cu_file.read()
    content += f"# main.cu\n```\n{main_cu_content}\n```\n"

# Save the content to prompt.txt
os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, 'w') as output_file:
    output_file.write(content)

print(f"Content has been saved to {output_path}")
