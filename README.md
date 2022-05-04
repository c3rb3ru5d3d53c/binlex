# binlex

<h2>A Genetic Binary Trait Lexer Library and Utility</h2>

The purpose of `binlex` is to extract basic blocks and functions as traits from binaries for malware research, hunting and detection.

Most projects attempting this use Python to generate traits, but it is very slow.

The design philosophy behind `binlex` is it to keep it simple and extendable.

The simple command-line interface allows malware researchers and analysts to hunt traits across hundreds or thousands of potentially similar malware saving time and money in production environments.

While the C++ API allows developers to get creative with their own detection solutions, completely unencumbered by license limitations.

To help combat malware, we firmly commit our work to the public domain for the greater good of the world.

[![Build status](https://ci.appveyor.com/api/projects/status/wa423scoigl7xh7x/branch/master?svg=true)](https://ci.appveyor.com/project/c3rb3ru5d3d53c/binlex)
![OS Linux](https://img.shields.io/badge/os-linux-brightgreen)
![OS Windows](https://img.shields.io/badge/os-windows-brightgreen)
[![GitHub stars](https://img.shields.io/github/stars/c3rb3ru5d3d53c/binlex)](https://github.com/c3rb3ru5d3d53c/binlex/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/c3rb3ru5d3d53c/binlex)](https://github.com/c3rb3ru5d3d53c/binlex/network)
[![Discord Status](https://img.shields.io/discord/915569998469144636?logo=discord)](https://discord.gg/UDBfRpxV3B)
[![GitHub license](https://img.shields.io/github/license/c3rb3ru5d3d53c/binlex)](https://github.com/c3rb3ru5d3d53c/binlex/blob/master/LICENSE)
![GitHub all releases](https://img.shields.io/github/downloads/c3rb3ru5d3d53c/binlex/total)


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

**Dependencies:**

To get started you will need the following dependencies for `binlex`.

```bash
sudo apt install -y git build-essential \
                    cmake make parallel \
                    doxygen git-lfs rpm \
                    python3 python3-dev
git clone --recursive https://github.com/c3rb3ru5d3d53c/binlex.git
cd binlex/
```

Please note that `binlex` requires `cmake` >= 3.5, `make` >= 4.2.1 and `ubuntu` >= 20.04.

Once you have installed, cloned and changed your directory to the project directory, we can continue with installation.

**From Source:**

If you want to compile and install via `make install` run the following commands:

```bash
make threads=4
sudo make install

# Test your installation
binlex -m elf:x86 -i tests/elf/elf.x86
```

**Binary Releases:**

See the [`releases`](https://github.com/c3rb3ru5d3d53c/binlex/releases) page.

If you need the bleeding edge binaries you can download them from our AppVeyor CI/CD [`here`](https://ci.appveyor.com/project/c3rb3ru5d3d53c/binlex/branch/master).

Please note, edge binaries are subject to bugs, if you encounter one, please let us know!

**Test Files:**
- To download all the test samples do the command `git lfs fetch`
- ZIP files in the `tests/` directory can then be extracted using the password `infected`

**Building Packages:**

Additionally, another option is to build Debian binary packages for and install those.

To build packages use `cpack`, which comes with `cmake`.

```bash
make threads=4
make pkg  # builds binary packages
make dist # builds source packages
sudo apt install ./build/binlex_1.1.1_amd64.deb
binlex -m elf:x86 -i tests/elf/elf.x86
```

You will then be provided with `.deb`, `.rpm` and `.tar.gz` packages for `binlex`.

**Building Python Bindings:**

To get started using `pybinlex`:
```bash
virtualenv -p python3 venv
source venv/bin/activate
# Install Library
pip install -v .
# Build Wheel Package
pip wheel -v -w build/ .
python3
>>> import pybinlex
```

If you wish to compile the bindings with `cmake`:
```bash
make python
```

Please note, we use `pybind11` and support for `python3.9` is experimental.

Examples of how to use `pybinlex` can be found in `tests.py`.

**Building Binlex Servers:**

Dependencies:
```bash
sudo apt install docker.io make
sudo usermod -a -G docker $USER
sudo systemctl enable docker
reboot # ensures your user is added to the docker group
```

Building:
```bash
make docker        # generate docker-compose.yml and config files
# Your generated credentials will be printed to the screen and saved in config/credentials.txt
make docker-build  # build the images (can take a long time, go get a coffee!)
make docker-start  # start the containers
make docker-init   # initialize all databases and generated configurations
make docker-logs   # tail all logs
```

Architecture (High Level):
```text
    ┌─────┐
┌─┬─►blapi│        (HTTP API)
│ │ └─────┘
│ │
│ │ ┌─────┐
│ ├─►bldec│        (decompile cluster)
│ │ └─────┘
│ │
│ │ ┌────┐
│ │ │bldb◄─────┬─┐ (database insert cluster)
│ │ └────┘     │ │
│ │            │ │
│ │ ┌─────┐    │ │
│ ├─►minio◄────┼─┤ (object store cluster)
│ │ └─────┘    │ │
│ │            │ │
│ │ ┌────────┐ │ │
│ └─►rabbitmq◄─┘ │ (messaging queue cluster)
│   └────────┘   │
│                │
│   ┌───────┐    │
└───►mongodb◄────┘ (document database cluster)
    └───────┘
```

If you wish to change the auto-generated initial username and passwords, you can run `./docker.sh` with additional parameters.

To see what parameters are available to you, run `./docker.sh --help`.

Your connection strings for MongoDB per user in this case would be:
- binlex - `mongodb://binlex:<generated-password>@127.0.0.1/?authSource=binlex` (for trait collection)
- admin - `mongodb://admin:<generated-password>@127.0.0.1` (for administration)

The HTTP API documentation is generated automatically, visit `https://127.0.0.1" in your browser to read.

To make requests to the API do the following:
```bash
curl --insecure -H "X-API-Key: <your-api-key-here>" https://127.0.0.1/binlex/version
```

If you work with a team of malware analysts or malware researchers, you create read-only accounts for them.

This will ensure they can do advanced queries to hunt and write detection signatures.

Adding New Read-Only Users to MongoDB:
```bash
cd scripts/
./mongodb-createuser.sh mongodb-router1 <username> <password>
```

If you have a VERY large team, you can script creation of these accounts.

# Basic Usage

```text
binlex v1.1.1 - A Binary Genetic Traits Lexer
  -i  --input           input file              (required)
  -m  --mode            set mode                (required)
  -lm --list-modes      list modes
  -c  --corpus          corpus name             (optional)
  -t  --threads         number of threads       (optional)
  -tc --thread-cycles   thread wait cycles      (optional)
  -ts --thread-sleep    thread sleep in ms      (optional)
  -to --timeout         execution timeout in s  (optional)
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
binlex -m raw:x86 -i tests/raw/raw.x86 | jq -r 'select(.type == "block" and .size < 32 and .size > 0) | .bytes'
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
jq -r 'select(.type == "block" and .size < 32 and .size > 0)'
# Function traits with a cyclomatic complexity greater than 32 (maybe obfuscation)
jq -r 'select(.type == "function" and .cyclomatic_complexity > 32)'
# Traits where bytes have high entropy
jq -r 'select(.bytes_entropy > 7)'
# Output all trait strings only
jq -r '.trait'
# Output only trait hashes
jq -r '.trait_sha256'
```

If you output just traits you want to `stdout` you can do build a `yara` signature on the fly with the included tool `blyara`:

```bash
build/binlex -m raw:x86 -i tests/raw/raw.x86 | jq -r 'select(.size > 16 and .size < 32) | .trait' | build/blyara --name example_0 -m author example -m tlp white -c 1
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

They will also contain additional properties about the trait including its `offset`, `edges`, `blocks`, `cyclomatic_complexity`, `average_instruction_per_block`, `bytes`, `trait`, `trait_sha256`, `bytes_sha256`, `trait_entropy`, `bytes_entropy`, `type`, `size`, `invalid_instructions` and `instructions`.

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

```cpp
#include <binlex/pe.h>
#include <binlex/decompiler.h>

using namespace binlex;

int main(int argc, char **argv){
  PE pe32;
  if (pe32.Setup(MACHINE_TYPES::IMAGE_FILE_MACHINE_I386) == false){
      return 1;
  }
  if (pe32.ReadFile("tests/pe/pe.x86") == false){
      return 1;
  }
  Decompiler decompiler;
  for (int i = 0; i < DECOMPILER_MAX_SECTIONS; i++){
      if (pe32.sections[i].data != NULL){
          decompiler.Setup(CS_ARCH_X86, CS_MODE_32, i);
          decompiler.SetMode("pe:x86", i);
          decompiler.SetFileSHA256(pe32.hashes.sha256, i);
          decompiler.SetCorpus("default", i);
          decompiler.AppendQueue(pe32.sections[i].functions, DECOMPILER_OPERAND_TYPE_FUNCTION, i);
          decompiler.Decompile(pe32.sections[i].data, pe32.sections[i].size, pe32.sections[i].offset, i);
      }
  }
  decompiler.PrintTraits(true);
  return 0;
}
```

# Python API Example Code

```python
#!/usr/bin/env python

import pybinlex
from hashlib import sha256

data = open('tests/pe/pe.x86', 'rb').read()
file_hash = sha256(data).hexdigest()
pe = pybinlex.PE()
decompiler = pybinlex.Decompiler()
pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_I386)
pe.read_buffer(data)
sections = pe.get_sections()
for i in range(0, len(sections)):
    decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, i)
    decompiler.set_mode("pe:x86", i)
    decompiler.set_corpus("default", i)
    decompiler.set_file_sha256(file_hash, i)
    decompiler.decompile(sections[i]['data'], sections[i]['offset'], i)
traits = decompiler.get_traits()
print(json.dumps(traits, indent=4))
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
