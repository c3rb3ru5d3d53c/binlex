# binlex

<h2>A Genetic Binary Trait Lexer Library and Utility<h2>

The purpose of `binlex` is to extract basic blocks and functions as traits from binaries.

Most projects attempting this use Python to generate traits, but it's slow. When working with a lot of malware binaries, it is much better to use a faster compiled language like C++.

# Use Cases
- YARA Signature Creation/Automation
- Identifying Code-Reuse
- Threat Hunting
- Machine Learning Malware Detection

# Installing

**From Source:**

```bash
sudo apt install -y git libcapstone-dev cmake make parallel
git clone https://github.com/c3rb3ru5d3d53c/binlex.git
cd binlex/
make threads=4
sudo make install
binlex -m elf:x86 -i tests/elf/elf.x86
```

**Binary Release:** See the [`releases`](https://github.com/c3rb3ru5d3d53c/binlex/releases) page.

**NOTE:**
- ZIP files in the `tests/` directory can be extracted using the password `infected`

# Usage

```text
binlex v1.0.1 - A Binary Genetic Traits Lexer
  -i  --input           input file              (required)
  -m  --mode            set mode                (required)
  -lm --list-modes      list modes
  -h  --help            display help
  -o  --output          output file             (optional)
  -v  --version         display version
Author: @c3rb3ru5d3d53c
```

**Currently Supported Modes**

- `elf:x86`
- `elf:x86_64`
- `pe:x86`
- `pe:x86_64`
- `raw:x86`
- `raw:x86_64`
- `raw:cil`

__NOTE:__ The `raw` formats can be used on shellcode

**Advanced Usage:**

If you have terabytes of executable files, we can leverage the power of `parallel` to generate traits for us.

```bash
make traits source=samples/malware/pe/x32/ dest=dist/ type=malware format=pe arch=x86 threads=4
make traits-combine source=dist/ dest=dist/ type=malware format=pe arch=x86 threads=4
```

It also allows you to name your type of dataset, i.e. goodware/malware/riskware/pua etc...

With `binlex` it is up to you to remove goodware traits from your extracted traits.

There have been many questions about removing "library code", there is a make target shown below to help you with this.

```bash
make traits-clean remove=goodware.traits source=sample.traits dest=malware.traits
```

With `binlex` the power is in your hands, "With great power comes great responsibility", it is up to you!

**Plugins:**

There has been some interest in making IDA, Ghidra and Cutter plugins for `binlex`.

This is something that will be started soon.

This `README.md` will be updated when they are ready to use.

**General Usage Information:**

Binlex is designed to do one thing and one thing only, extract genetic traits from executable code in files. This means it is up to you "the researcher" / "the data scientist" to determine which traits are good and which traits are bad. To accomplish this, you need to use your own [fitness function](https://en.wikipedia.org/wiki/Fitness_function). I encourage you to read about [genetic programming](https://en.wikipedia.org/wiki/Genetic_programming) to gain a better understanding of this in practice. Perhaps watching [this](https://www.youtube.com/watch?v=qiKW1qX97qA) introductory video will help your understanding.

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

# Future Work
- Java Bytecode Support `raw:jvm`, `java:jvm`
- Cutter, Ghidra and IDA Plugins
- .NET PE support `pe:cil`
- Mac-O Support `macho:x86_64`, `macho:x86`

# Contributing

If you wish to contribute to Binlex DM me on Twitter https://twitter.com/c3rb3ru5d3d53c.

Currently looking for help on:
- MacOS Developer (Parse Mach-O)
- Plugin Developers (Python)
