# binlex

<h2>A Genetic Binary Trait Lexer Library and Utility</h2>

The purpose of `binlex` is to extract basic blocks and functions as traits from binaries for malware research, hunting and detection.

Most projects attempting this use Python to generate traits, but it is very slow.

The design philophy behind `binlex` is it to keep it simple and extensable.

The simple command-line interface allows malware researchers and analysts to hunt traits across hundreds or thousands of potentially similar malware saving time and money in production environments.

While the C++ API allows developers to get creative with their own detection solutions.

# Demos

<p align="center">
  <img src="docs/img/demo_0.gif" alt="animated" />
</p>

# Introduction Video

<p align="center">
  <a href="https://www.youtube.com/watch?v=hgz5gZB3DxE" target="_blank">
    <img src="https://img.youtube.com/vi/hgz5gZB3DxE/0.jpg" alt="Introduction Video">
  </a>
</p>

Get slides [here](docs/oalabs.pdf).

# Use Cases
- YARA Signature Creation/Automation
- Identifying Code-Reuse
- Threat Hunting
- Building Goodware Trait Corpus
- Building Malware Trait Corpus
- Genetic Programming
- Machine Learning Malware Detection

# Installing

**From Source:**

Please note that `binlex` requires `cmake` >= 3.5 and `make` >= 4.2.1.

```bash
sudo apt install -y git build-essential libcapstone-dev cmake make parallel doxygen git-lfs
git clone --recursive https://github.com/c3rb3ru5d3d53c/binlex.git
cd binlex/
make threads=4
sudo make install
binlex -m elf:x86 -i tests/elf/elf.x86
```

**Binary Release:** See the [`releases`](https://github.com/c3rb3ru5d3d53c/binlex/releases) page.

**NOTE:**
- ZIP files in the `tests/` directory can be extracted using the password `infected`

# Basic Usage

```text
binlex v1.1.0 - A Binary Genetic Traits Lexer
  -i  --input           input file              (required)
  -m  --mode            set mode                (required)
  -lm --list-modes      list modes
  -h  --help            display help
  -o  --output          output file             (optional)
  -p  --pretty          pretty output           (optional)
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
- `raw:cil` (experimental)

__NOTE:__ The `raw` formats can be used on shellcode

# Advanced Usage

If you are hunting using `binlex` you can use `jq` to your advantage for advanced searches.

```bash
binlex -m raw:x86 -i tests/raw/raw.x86 | jq -r '.[] | select(.type == "block" and .size < 32 and .size > 0) | .bytes'
2c 20 c1 cf 0d 01 c7 49 75 ef
52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c
01 d0 50 8b 58 20 8b 48 18 01 d3 85 c9 74 3c
49 8b 34 8b 01 d6 31 ff 31 c0 c1 cf 0d ac 01 c7 38 e0 75 f4
03 7d f8 3b 7d 24 75 e0
58 5f 5a 8b 12 e9 80 ff ff ff
ff 4e 08 75 ec
e8 67 00 00 00 6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 83 f8 00 7e 36
e9 9b ff ff ff
01 c3 29 c6 75 c1
```

Other queries you can do:
```bash
# Block traits with a size between 0 and 32 bytes
jq -r '[.[] | select(.type == "block" and .size < 32 and .size > 0)]'
# Function traits with a cyclomatic complexity greater than 32 (maybe obfuscation)
jq -r '[.[] | select(.type == "function" and .cyclomatic_complexity > 32)]'
# Traits where bytes have high entropy
jq -r '[.[] | select(.bytes_entropy > 7)]'
# Output all trait strings only
jq -r '.[] | .trait'
# Output only trait hashes
jq -r '.[] | .trait_sha256'
```

If you output just traits you want to `stdout` you can do build a `yara` signature on the fly with the included tool `blyara`:

```bash
build/binlex -m raw:x86 -i tests/raw/raw.x86 | jq -r '.[] | select(.size > 16 and .size < 32) | .trait' | build/blyara --name example_0 -m author example -m tlp white -c 1
rule example_0 {
    metadata:
        author = "example"
        tlp = "white"
    strings:
        trait_0 = {52 57 8b 52 ?? 8b 42 ?? 01 d0 8b 40 ?? 85 c0 74 4c}
        trait_1 = {49 8b 34 8b 01 d6 31 ff 31 c0 c1 cf ?? ac 01 c7 38 e0 75 f4}
        trait_2 = {e8 67 00 00 00 6a 00 6a ?? 56 57 68 ?? ?? ?? ?? ff d5 83 f8 00 7e 36}
    condition:
        1 of them
}
```

You can also use the switch `--pretty` to output `json` to identify more properies to query.

```bash
binlex -m pe:x86 -i tests/pe/pe.trickbot.x86 --pretty
[
  {
    "average_instructions_per_block": 29,
    "blocks": 1,
    "bytes": "ae 32 c3 32 1a 33 25 34 85 39 ae 3b b4 3b c8 3b 35 3c 3a 3c 6b 3c 71 3c 85 3c aa 3d b0 3d 6a 3e a5 3e b8 3e fd 3e 38 3f 4b 3f 87 3f 00 20 00 00 58 00 00 00 4f 30 aa 30 01 31 1d 31 ac 31 d6 31 e5 31 f5 31 1c 32 31 32 75 34",
    "bytes_entropy": 5.070523738861084,
    "bytes_sha256": "67a966fe573ef678feaea6229271bb374304b418fe63f464b71af1fbe2a87f37",
    "cyclomatic_complexity": 3,
    "edges": 2,
    "instructions": 29,
    "offset": 11589,
    "size": 74,
    "trait": "ae 32 c3 32 1a 33 25 ?? ?? ?? ?? 3b b4 3b ?? ?? ?? ?? 3a 3c 6b 3c 71 3c 85 3c aa 3d b0 3d 6a 3e a5 3e b8 3e fd 3e 38 3f 4b 3f 87 3f 00 20 00 00 58 00 00 00 4f ?? aa 30 01 31 1d ?? ?? ?? ?? 31 e5 31 f5 31 1c 32 31 32 75 34",
    "trait_entropy": 4.9164042472839355,
    "trait_sha256": "a00fcb2b23a916192990665d8a5f53b2adfa74ec98991277e571542aee94c3a5",
    "type": "block"
  }
]
```

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

They will also contain additional properties about the trait including its `offset`, `edges`, `blocks`, `cyclomatic_complexity`, `average_instruction_per_block`, `bytes`, `trait`, `trait_sha256`, `bytes_sha256`, `trait_entropy`, `bytes_entropy`, `type`, `size`, and `instructions`.

```
[
  {
    "average_instructions_per_block": 29,
    "blocks": 1,
    "bytes": "ae 32 c3 32 1a 33 25 34 85 39 ae 3b b4 3b c8 3b 35 3c 3a 3c 6b 3c 71 3c 85 3c aa 3d b0 3d 6a 3e a5 3e b8 3e fd 3e 38 3f 4b 3f 87 3f 00 20 00 00 58 00 00 00 4f 30 aa 30 01 31 1d 31 ac 31 d6 31 e5 31 f5 31 1c 32 31 32 75 34",
    "bytes_entropy": 5.070523738861084,
    "bytes_sha256": "67a966fe573ef678feaea6229271bb374304b418fe63f464b71af1fbe2a87f37",
    "cyclomatic_complexity": 3,
    "edges": 2,
    "instructions": 29,
    "offset": 11589,
    "size": 74,
    "trait": "ae 32 c3 32 1a 33 25 ?? ?? ?? ?? 3b b4 3b ?? ?? ?? ?? 3a 3c 6b 3c 71 3c 85 3c aa 3d b0 3d 6a 3e a5 3e b8 3e fd 3e 38 3f 4b 3f 87 3f 00 20 00 00 58 00 00 00 4f ?? aa 30 01 31 1d ?? ?? ?? ?? 31 e5 31 f5 31 1c 32 31 32 75 34",
    "trait_entropy": 4.9164042472839355,
    "trait_sha256": "a00fcb2b23a916192990665d8a5f53b2adfa74ec98991277e571542aee94c3a5",
    "type": "block"
  }
]
```

# Documentation

Public documentation on `binlex` can be viewed [here](https://c3rb3ru5d3d53c.github.io/binlex/html/index.html).

# Building Docs

You can access the C++ API Documentation and everything else by building the documents using `doxygen`.

```bash
make docs threads=4
```

The documents will be available at `build/docs/html/index.html`.

# C++ API Example Code

It couldn't be any easier to leverage `binlex` and its C++ API to build your own applications.

See example code below:

```cpp
#include <binlex/pe.h>
#include <binlex/decompiler.h>

using namespace binlex;

int main(int argc, char **argv){
  Pe pe32;
  if (pe32.Setup(PE_MODE_X86) == false){
      return 1;
  }
  if (pe32.ReadFile(argv[1]) == false){
      return 1;
  }
  Decompiler decompiler;
  decompiler.Setup(CS_ARCH_X86, CS_MODE_32);
  for (int i = 0; i < PE_MAX_SECTIONS; i++){
      if (pe32.sections[i].data != NULL){
          decompiler.x86_64(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
      }
  }
  decompiler.PrintTraits(args.options.pretty);
}
```

We hope this encourages people to build their own detection solutions based on binary genetic traits.

# Tips
- If you are hunting be sure to use `jq` to improve your searches
- Does not support PE files that are VB6 or .NET if you run against these you will get errors
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
- Recursive Decompiler
- Java Bytecode Support `raw:jvm`, `java:jvm`
- Cutter, Ghidra and IDA Plugins
- .NET support `pe:cil` and `raw:cil`
- Mac-O Support `macho:x86_64`, `macho:x86`

# Contributing

If you wish to contribute to Binlex DM me on Twitter [here](https://twitter.com/c3rb3ru5d3d53c).

You can also join our Discord [here](https://discord.gg/UDBfRpxV3B).

Currently looking for help on:
- MacOS Developer (Parse Mach-O)
- Plugin Developers (Python)
