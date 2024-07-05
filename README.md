# XOR-Cipher-and-Bruteforcer
Implementation of the XOR cipher in C and a one-digit key bruteforcing tool to discover an encrypted text. 

# XOR Cipher Implementation
## Compile
```sh
gcc xor.c cryptoutils.c -ansi -Wall -o xor
```
## Run
```
$ ./xor 41636f72646150656472696e686f517565686f6a6574656d63616d70656f6e61746f 0b021e0701003e0a0d060c0807063d1a0b0f0e060a1a020c0f0e03170403010f130e

Ciphertext:     4a61717565616e6f697465666f696c6f6e67616c6f6e67616c6f6e67616c6f6e6761
Base64:         SmFxdWVhbm9pdGVmb2lsb25nYWxvbmdhbG9uZ2Fsb25nYQ==
```

# Xor One-Digit Bruteforcer
Receives as input a XOR ciphertext and tries to bruteforce it with 2-40 byte keys.
## Compile
```sh
gcc bruteforcer.c cryptoutils.c -ansi -Wall -o bruteforcer
```
## Run
```
$ ./bruteforcer 072c232c223d2c3e3e2c2328232538202e2c3f3f223d223f2c3c3824072c232c223d2c3e3e2c2328232538202b24212028232c191b1b222e283c382828233f22212c2238393f222e242a2c3f3f223d223f2c2408232c22292c2f22212c3d3f223c38283b2c242c2e222339282e283f002c243e38203d22382e2228202c243e382
```
