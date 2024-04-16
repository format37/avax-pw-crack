export CUDA_VISIBLE_DEVICES=1

rm -rf run.log
./program >> run.log
cat run.log
