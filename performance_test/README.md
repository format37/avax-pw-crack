# Performance evaluation
This subsystem is aimed to determine how much time and resources is required for searching the word in a worst case scenario.
### Build
Define your gpu architecture
```
cd ../docker
sh build.sh sm_61
cd ../performance_test
```
### Run
You can run both CPU and GPU tests simultaneously by running the following commands in a separate shell:
```
python test.py cpu
python test.py gpu
```
### Report
```
python report.py
```