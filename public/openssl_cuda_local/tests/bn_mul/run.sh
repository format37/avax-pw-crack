# Set the desired GPU device ID (0, 1, 2, etc.)
export CUDA_VISIBLE_DEVICES=0

rm -rf run.log
./program >> run.log
cat run.log
