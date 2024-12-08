# avax-pw-crack

This repo contains a utility that able to find the 25th word of your bitcoin seed phrase.
You still need to know the first 24 words, and you also need a guess at the 25th word.
Finally, you need either your p-chain address to match against.

##### Input:
* mnemonic
* start_passphrase
* end_passphrase
* p_chain_address

##### Output:
* 25th word

#### Set max word length
It is crucial to set the max word length in the main.cu
```
#define MAX_PASSPHRASE_LENGTH 8 // 7-letter word + null terminator.
```

#### Simple docker example
Clone the repo
```
git clone https://github.com/format37/avax-pw-crack.git
cd avax-pw-crack/cuda
```
Define your GPU architecture in the 
```
nano entrypoint.sh
```
Compose
```
sh compose.sh
```

#### Cuda usage
You need to define the input parameters in the cuda/config.json
Start from small search space (short threashold between start and end passphrase) to determine the performance and increase it gradually.
```
cd cuda
sh build_and_run.sh
```

#### conda cuda installation
```
conda install -c conda-forge pycuda
sudo apt install nvidia-cuda-toolkit
```
#### crypto sources & docs
[crypto-cuda](https://github.com/peihongch/crypto-cuda/)
[bip-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
[libgpucrypto](https://shader.kaist.edu/sslshader/libgpucrypto/)

#### Profiling with Nsight Compute in linux:
* (Optional) install dbus if required:
```
sudo apt install dbus
dbus-launch
```
* Disable the Watchdog Timer:
```
sudo nano /etc/X11/xorg.conf
```
Find the section and do the following changes:
```
Section "Device"
    Identifier "Device0"
    Driver     "nvidia"
    Option     "Interactive" "0"
EndSection
```
* Restart the system.
* Run profiler from cmd:
```
/opt/nvidia/nsight-compute/2024.1.1/ncu --verbose ./program
```
or from GUI:
```
/opt/nvidia/nsight-compute/2024.1.1/ncu-ui
```