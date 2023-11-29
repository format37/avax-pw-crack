Check include paths for openssl:
```
grep -rnl '/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/' -e 'include <openssl'
grep -rnl '/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/' -e 'include <crypto'
grep -rnl '/home/alex/projects/avax-pw-crack/public/openssl_cuda_local/include/' -e 'include <internal'
```
Search for openssl lib path:
```
find / -name err.h 2>/dev/null
# /mnt/hdd0/alex/anaconda3/envs/crack/include/openssl/
```