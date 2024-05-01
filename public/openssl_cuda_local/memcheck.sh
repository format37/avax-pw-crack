export CUDA_VISIBLE_DEVICES=0

# cuda-memcheck --leak-check full --flush-to-disk yes --log-file memcheck.log --save memcheck.errors ./program 
compute-sanitizer --tool memcheck --leak-check full --flush-to-disk yes --log-file memcheck.log --save memcheck.errors ./program 
