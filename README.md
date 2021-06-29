# BinLex a Genetic Binary Trait Lexer Library and Utility

The purpose of BinLex is to extract basic blocks and functions as traits from binaries.

Most projects attempting this use Python to generate traits, but it's slow. When working with a lot of malware binaries, it is much better to use a faster compiled language like C++.

# Installing
```bash
sudo apt install -y git libcapstone-dev cmake make
git clone https://github.com/c3rb3ru5d3d53c/binlex.git
cd binlex/
mkdir -p build/
cd build/ && cmake -S ../ -B . && make -j 4
sudo make install
cd ../
binlex -m elf:x86 -i tests/elf/elf.x86
```

**NOTE:**
- ZIP files in the `tests/` directory can be extracted using the password `infected`

# Usage

```text
binlex v1.0.0 - A Binary Genetic Traits Lexer
  -i  --input           input file or directory         (required)
  -m  --mode            set mode                        (required)
  -lm --list-modes      list modes
  -h  --help            display help
  -t  --threads         threads
  -o  --output          output file or directory        (optional)
  -v  --version         display version
Author: @c3rb3ru5d3d53c
```

**Currently Supported Modes**
- elf:x86
- elf:x86_64
- pe:x86
- pe:x86_64
- raw:x86     (useful for shellcode)
- raw:x86_64  (useful for shellcode)

Binlex is designed to do one thing and one thing only, extract genetic traits from executable code in files.

This means it is up to you "the researcher" / "the data scientist" to determine which traits are good and which traits are bad.

To accomplish this, you need to use your own [fitness function](https://en.wikipedia.org/wiki/Fitness_function).

I encourage you to read about [genetic programming](https://en.wikipedia.org/wiki/Genetic_programming) to gain a better understanding of this in practice.

Perhaps watching [this](https://www.youtube.com/watch?v=qiKW1qX97qA) introductory video will help your understanding.

Again, **it's up to you to implement your own algorithms for detection based on the genetic traits you extract**.

# Trait Format
Traits will contain binary code represented in hexadecimal form and will use `??` as wild cards for memory operands or other operands subject to change.

Trait files will contain a list of traits ordered by size and use the sha256 of the sample as the file name.

```
# Example Trait File
12 34 56 ?? ?? 11 12 13
14 15 16 17 18 ?? ?? 21 22 23
# ... More traits to follow
```

# Tips
- Don't mix packed and unpacked malware or you will taint your dataset (seen this in academics all the time)
- Verify the samples you are collecting into a group using skilled analysts
- These traits are best used with a hybrid approach (supervised)

# Example Fitness Model

Traits will be compared amongst their common malware family, any traits not common to all samples will be discarded.

Once completed, all remaining traits will be compared to traits from a goodware set, any traits that match the goodware set will be discarded.

To further differ the traits from other malware families, the remaining population will be compared to other malware families, any that match will be discarded.

The remaining population of traits will be unique to the malware family tested and not legitimate binaries or other malware families.

This fitness model allows for accurate classification of the tested malware family.
