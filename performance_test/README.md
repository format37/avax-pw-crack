# Performance evaluation
This subsystem is aimed to determine how much time and resources is required for searching the word in a worst case scenario.
In addition we are able to compute the performance of each device which is crucial when devices has different performance.
### Build
Define your gpu architecture
```
cd ../docker
sh build.sh sm_61
cd ../performance_test
```

### Initial configuration
Define architecture and device id for GPU device that you plan to evaluate in the config.json file.

### Test GPU
To test the defined GPU device perfrormance, run:
```
python test.py gpu
```
### Test CPU
You can simpultaneously run the CPU test if you interested in non-GPU performance evaluation
```
python test.py cpu
```
### Interruption
You can stop evaluation any time by pressing Ctrl+C and for GPU test run:
```
python combine_results.py gpu
```

### Report
```
python fit_linear.py
```