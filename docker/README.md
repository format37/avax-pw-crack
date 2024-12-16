## Multiple-gpu docker 25th word searching
### Configuration
1. Define config.json:
* mnemonic: Known 24-word seed phrase.
* p_chain_address: Avalanche P-chain address, which I guess can be obtained on-chain. For example, at [avascan.info](https://avascan.info/blockchain/p/home) about your transaction.
* alphabet: You can drop some symbols if you are confident that it has not been used in 25th word. Pay attention to capital letters and symbols like I, l, |
* start_passphrase: If we imagine the telephone book, it has names: A, B, ... Z, AA, AB .. So then if the alphabet has only capital letters, the search area from A to AA would be 32 words. There you can define the search area, where start_passphrase is a left boundary.
* start_passphrase: Right boundary of the search area.
* instances: Count of GPUs that you plan to utilize. Single GPU is acceptable too.
* cuda architecture: The architecture of GPU that you plan to use. There is suggested to define architecture for most of your GPUs. You can redefine the architecture in config for each GPU later. The architecture table for some of GPUS is represented below.
  
| GPU Model            | Architecture | Compute Capability | `sm_xx` Definition |
|----------------------|--------------|--------------------|--------------------|
| NVIDIA A100          | Ampere       | 8.0                | `sm_80`            |
| NVIDIA A40           | Ampere       | 8.6                | `sm_86`            |
| NVIDIA V100          | Volta        | 7.0                | `sm_70`            |
| NVIDIA T4            | Turing       | 7.5                | `sm_75`            |
| NVIDIA P100          | Pascal       | 6.0                | `sm_60`            |
| NVIDIA K80           | Kepler       | 3.7                | `sm_37`            |
| NVIDIA RTX 4090      | Ada Lovelace | 8.9                | `sm_89`            |
| NVIDIA GTX 1080      | Pascal       | 6.1                | `sm_61`            |
| NVIDIA GTX 1060      | Pascal       | 6.1                | `sm_61`            |
  
If your GPU is not listed above, you can google your architecture.
    
## Build images
Update the build.sh script rights:
```
chmod +x build.sh
```
For each architecture that you plan to utilize. For example:
```
./build.sh sm_86
./build.sh sm_61
```
You can check existing images with command:
```
sudo docker images
```

## Generate configs
```
python -m pip install requirements.txt
python generate_configs.py
```
If you have GPUs with a different architecture, you need to update the corresponding configs in the `./config` folder.
If you plan to run serach on a multiple machines, move each GPU config from ./configs folder to the corresponding machine.

## Generate docker-compose
```
python generate_docker_compose.py
```

## Run the search
```
sudo docker-compose up
```

## Monitoring:
* GPU utilization:
```
nvtop
```
* Docker health
```
sudo docker ps
```
* Container logs:
```
sudo docker logs -f searcher_0
```

## Results
When one of the instances found the word, this word is saved to txt file in the ./results folder. Other instances will not stop their job.