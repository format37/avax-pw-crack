# Performance evaluation
This subsystem is aimed to determine how much time and resources is required for searching the word in a worst case scenario.
In addition we are able to compute the performance of each device which is crucial when devices has different performance.
### Build
Define your gpu architecture
```
cd ../docker
sh build.sh sm_89 # Ada Lovelace architecture
cd ../performance_test
```

### Initial configuration
Define architecture and device id for GPU device that you plan to evaluate in the config.json file.  
  
You can define the p_chain_export flag as 1 if you need to check the consistency of the search area.
For example, if search area from 0 to 1 includes ['A','B','C'] then the search area is consistent. This can prove that all possible adresses in boundaries will be calculated.
The only first 11000000 p-chain adresses can be exported, others will be skipped. Enabling this flag will influence on performance, so it should be used only for consistency test and should not be used for performance tests.

### Test GPU
To test the defined GPU device perfrormance, run:
```
python test.py gpu
```
### Test CPU
The non-GPU performance evaluation
```
python test.py cpu
```

### Report
You can stop evaluation any time by pressing Ctrl+C after completing 3+ tests.
```
python report.py gpu
```
This gives you the performance evaluation of the chosen device, that can be used in the load distribution configuration further.

### Consistency check
Take the name of report file. This filename can be obtained in the test run logs. It is usually the last *.tsv file in the gpu_results folder. Then run (update your filename):
```
python check_p_chain_consistency.py gpu_results/p_chain_addresses_f2566330-925b-49fe-a9a6-a2b9d6a36c8b.tsv
```
If result is consistent that means that all expected IDs is found in the actual IDs.