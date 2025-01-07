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