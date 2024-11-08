import os

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

# Example usage
extensions = ['cu', 'h', 'c', 'py', 'log', 'md']
folders = [
    # "~/projects/temp/cuda-fixnum/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-add/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-sub/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-mul/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-div/",
    # "~/projects/avax-pw-crack/cuda/tests/fixnum-divmod/"
    
    # "../include/",

    # "~/projects/openssl/include/openssl/ec.h",
    # "~/projects/openssl/crypto/ec/ec_lib.c",  
    # "~/projects/openssl/include/openssl/bn.h",
    # "~/projects/openssl/crypto/bn/bn_mont.c",
    # "~/projects/openssl/crypto/ec/ec_mult.c",
    # "~/projects/openssl/crypto/ec/ec_local.h",
    # "~/projects/openssl/crypto/ec/ecp_smpl.c",
    # "~/projects/openssl/crypto/ec/ecp_mont.c",
    # "~/projects/openssl/crypto/bn/bn_mont.c",
    # "~/projects/openssl/crypto/bn/bn_sparc.c",
    # "~/projects/openssl/crypto/bn/bn_ppc.c",
    # "~/projects/openssl/crypto/bn/bn_asm.c"
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_scalar_mul_montgomery/test.c",
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_scalar_mul_montgomery/run.log",
    # "~/projects/openssl/crypto/ec/ecp_smpl.c",
    # "~/projects/openssl/crypto/ec/ec_local.h",
    # "~/projects/avax-pw-crack/openssl/tests/BN_mod_mul_montgomery/test.c",
    # "~/projects/avax-pw-crack/openssl/tests/BN_mod_mul_montgomery/run.log",
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_ladder_step/test.c",
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_ladder_step/run.log",
    "~/projects/openssl/crypto/bn/bn_exp.c",
    "~/projects/avax-pw-crack/cuda/prompts/111_BN_mod_exp_mont_description.md",
    "~/projects/avax-pw-crack/cuda/include/montgomery.h",
    # "~/projects/avax-pw-crack/openssl/tests/BN_mod_exp_mont/test.c",
    # "~/projects/avax-pw-crack/openssl/tests/BN_mod_exp_mont/build.log",
    # "~/projects/avax-pw-crack/openssl/tests/BN_mod_exp_mont/run.log",    
    "~/projects/avax-pw-crack/cuda/tests/BN_mod_exp_mont/test.cu",
    "~/projects/avax-pw-crack/cuda/tests/BN_mod_exp_mont/build.log",
    # "~/projects/avax-pw-crack/cuda/tests/BN_mod_exp_mont/run.log",
    # "~/projects/avax-pw-crack/cuda/prompts/112_bn_mul_mont_fixed_top.md",
    # # "~/projects/avax-pw-crack/cuda/include/bignum.h",
    # "~/projects/avax-pw-crack/cuda/include/point.h",
    # # "~/projects/avax-pw-crack/cuda/include/jacobian_point.h",
    # # "~/projects/avax-pw-crack/cuda/include/public_key.h",    
    
    # "~/projects/avax-pw-crack/cuda/tests/BN_mod_mul_montgomery_cuda/test.cu",
    # "~/projects/avax-pw-crack/cuda/tests/ec_point_scalar_mul_montgomery/test.cu",
    # # "~/projects/avax-pw-crack/cuda/tests/ec_point_scalar_mul_montgomery/run.log",    
    
    
    # "~/projects/avax-pw-crack/python/tests/bn_mul_mod_montgomery/test.py",
    # "~/projects/avax-pw-crack/python/tests/bn_mul_mod_montgomery/run.log",
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_scalar_mul_montgomery/test.c",
    # "~/projects/avax-pw-crack/cuda/tests/ec_point_scalar_mul_montgomery/test.cu",
    # "~/projects/avax-pw-crack/openssl/tests/ec_point_scalar_mul_montgomery/run.log",
    # "~/projects/avax-pw-crack/cuda/tests/ec_point_scalar_mul_montgomery/run.log",
    
    # "~/projects/avax-pw-crack/cuda/tests/bn_div/test.cu",
    # "~/projects/avax-pw-crack/cuda/tests/BN_mod_mul_montgomery_cuda/test.cu",
    # "~/projects/avax-pw-crack/cuda/tests/BN_mod_mul_montgomery_cuda/run.log",
    # "../main.cu",
    # "../logs/run.log",
    ]

output_path = "./prompt.md"

collect_file_contents(folders, extensions, output_path)
