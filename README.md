# avax-pw-crack
This repo contains a utility that aimed to find the 25th word of your bitcoin seed phrase utilizing the CUDA acceleration.  
You still need to know the first 24 words, and you also need a guess at the 25th word.  
Finally, you need either your p-chain address to match against.  

The multiple GPU devices utilization on the multiple machines is acceptable.  
  
##### Input:
* mnemonic  
* p_chain_address  
* alphabet  
* start_passphrase  
* end_passphrase  
* device architecture  
  
##### Output:
* 25th word  

## Docker
To use Docker for search follow the [Docker](https://github.com/format37/avax-pw-crack/tree/main/docker) insctructions.  

## CUDA source
Building from source is described in the [Cuda](https://github.com/format37/avax-pw-crack/tree/main/cuda) folder.  

## Performance evaluation
The performance equation for this task is $time = \frac{Penalty \times Search area + Bias}{GPU device count}$  
  
For the single 4090 GPU the Penalty is 0.0000142600841297 which means that it can solve approximately 70,126 combinations per second.  
  
The alphabet has 94 symbols max.  
The ledger's 25th word is 100 symbols max.  

The Penalty of the single CPU is 0.0522797826 so 4090 GPU can do this job ~3666 times faster.
  
The performance evaluation for your device can be performed in the (performance_test)[https://github.com/format37/avax-pw-crack/tree/main/performance_test] folder.
  