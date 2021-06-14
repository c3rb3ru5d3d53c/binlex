# BinLex a Genetic Binary Trait Lexer Library and Tool

The purpose of BinLex is to extract basic blocks and functions as traits from binaries then compare these traits amonst other trait sets using genetic programming.

Most projects attempting this use Python to generate traits, but it's slow. When working with a lot of malware binaries, it is much better to use a faster compiled language like C++.

This project is intended to help data scientists and other researchers to collect meaningful traits when developing their detection solutions.

# Installing
```bash
sudo apt install -y git libcapstone-dev cmake make
git clone https://github.com/c3rb3ru5d3d53c/binlex.git
cd binlex/
mkdir -p build/
cd build/ && cmake -S ../ -B . && make -j 4
sudo make install
binlex --help
```

# Trait Format
Traits will contain binary code represented in hexadecimal form and will use `??` as wild cards for memory operands or other operands subject to change.

Trait files will contain a list of traits ordered by size and use the sha256 of the sample as the file name.

```
# Example Trait File
12 34 56 ?? ?? 11 12 13
14 15 16 17 18 ?? ?? 21 22 23
# ... More traits to follow
```

# Example Fitness Model
Traits will be compared amongst their common malware family, any traits not common to all samples will be discarded.

Once completed, all remaining traits will be compared to traits from a goodware set, any traits that match the goodware set will be discarded.

To further differ the traits from other malware families, the remaining population will be compared to other malware families, any that match will be discarded.

The remaining population of traits will be unique to the malware family tested and not legitimate binaries or other malware families.

This fitness model allows for accurate classification of the tested malware family.
