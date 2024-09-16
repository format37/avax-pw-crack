# avax-pw-crack

This repo contains a utility that helps you crack the 25th word of your seed phrase.
You still need to know the first 24 words, and you also need a guess at the 25th word.
Finally, you need either your c-chain or p-chain address to match against.

I haven't done any work on typos.py to validate how good it is. I stole it from this
repo: https://github.com/alexbowe/bitcoin-passphrase-cracker

That repo is a bit out of date for the `bip_utils` library version, so I updated the
code and simplified it a little. I also added support for matching against p-chain
addresses.

I tested this with a sample seed and passphrase and it seems to work at least for small
differences. I ran this with python3.9, but I think it should work with most py3 versions.

If you need to install python, follow these
directions: https://linuxize.com/post/how-to-install-python-3-9-on-debian-10/

You'll also need to install the dependencies in requirements.txt:

```commandline
pip3.9 install -r requirements.txt 
```

You'll need to edit the contents of `crack_key.py` to contain the 24 words you know,
your best guess, and your p-chain address.

Finally, run the job using:

```commandline
python3.9 crack_key.py
```

This could take a very long time to run. If your guess is bad, or you have the wrong
24 seed phrase words, it won't work at all.

Python is single threaded, but if you have multiple guesses, you can run them in parallel.
Just copy/paste the script and make sure each includes the guess you want to try.

### Testing the CPU inference speed
1. Generate a test dataset:
```
python3 test_dataset.py
```
2. Run the test:
```
sh profile.sh
sh report.sh
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
#### CUDA implementation notes
Having unique test_passphrase and mnemonic, each thread need to:  
* Generate base_child.  
* Make 10 child_to_avaxp_address.  
* Compare each avaxp address with the target address.  
* If avaxp and target are matches, then put avaxp address to the target fariable and set stop_brute_forcing flag to true.  
* If stop_brute_forcing is true then exit from the searching loop.  

# Profiling with Nsight Compute in linux:
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