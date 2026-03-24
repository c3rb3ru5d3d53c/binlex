# Command-Line

The simplest way to get started is with the command-line, leveraging a JSON filtering tool like `jq`.

To see what options are available when using the `binlex` command-line use `-h` or `--help`.

```bash
binlex --help
```

## Making a YARA Rule

General workflow to extract 10 wildcarded YARA hex strings from a sample:

```bash
binlex -i sample.dll --threads 16 | jq -r 'select(.size >= 16 and .size <= 32 and .chromosome.pattern != null) | .chromosome.pattern' | sort | uniq | head -10
016b??8b4b??8bc74c6bd858433b4c0b2c0f83c5??????
01835404????c6836a0400????837e04??
03c04c8d05????????4863c8420fb60401460fb64401018942??85c074??
03c38bf0488d140033c9ff15????????488bd84885c075??
03c6488d55??41ffc58945a?41b804000000418bcce8b8fd01??eb??
03c6488d55??41ffc58945a?41b804000000418bcce8e3fb01??eb??
03f7488d05????????4883c310483bd87c??
03fb4c8bc6498bd7498bcc448d0c7d04000000e89409????8bd84885f6
03fe448bc6488bd3418bcee8d8e501??85ed
03fe897c24??397c24??0f867301????
```

After `uniq`, you can collapse similar same-length patterns:

```bash
awk 'NR==1{n=length($0);first=$0;delete v;split(tolower($0),v,"");cnt=1;next}{L=length($0);if(L==n){split(tolower($0),b,"");for(i=1;i<=n;i++){c=b[i];if(c=="?"){v[i]="?";next}if(!(i in v)||v[i]==""){v[i]=c}else if(v[i]!="?"&&v[i]!=c){v[i]="?"}};cnt++}else{if(cnt==1)print first;else{out="";for(i=1;i<=n;i++)out=out (i in v?v[i]:"?");print out};n=L;first=$0;delete v;split(tolower($0),v,"");cnt=1}}END{if(NR){if(cnt==1)print first;else{out="";for(i=1;i<=n;i++)out=out (i in v?v[i]:"?");print out}}}'
```

Then generate a quick rule using `binlex-yara`:

```bash
binlex -i sample.dll --threads 16 | jq -r 'select(.size >= 16 and .size <= 32 and .chromosome.pattern != null) | .chromosome.pattern' | sort | uniq | head -10 | binlex-yara -n example
rule example {
    strings:
        $trait_0 = {016b??8b4b??8bc74c6bd858433b4c0b2c0f83c5??????}
        $trait_1 = {01835404????c6836a0400????837e04??}
        $trait_2 = {03c04c8d05????????4863c8420fb60401460fb64401018942??85c074??}
        $trait_3 = {03c38bf0488d140033c9ff15????????488bd84885c075??}
        $trait_4 = {03c6488d55??41ffc58945a?41b804000000418bcce8b8fd01??eb??}
        $trait_5 = {03c6488d55??41ffc58945a?41b804000000418bcce8e3fb01??eb??}
        $trait_6 = {03f7488d05????????4883c310483bd87c??}
        $trait_7 = {03fb4c8bc6498bd7498bcc448d0c7d04000000e89409????8bd84885f6}
        $trait_8 = {03fe448bc6488bd3418bcee8d8e501??85ed}
        $trait_9 = {03fe897c24??397c24??0f867301????}
    condition:
        1 of them
}
```

If you exported genomes from the IDA plugin or another source, you can filter for naming prefixes like `mw::` (for malware).

Function JSON stores `blocks` as a list of block addresses rather than embedded block objects. If you need block metadata, consume standalone block entries from the same stream and join by address.

## Using Rizin with Binlex

Pipeline Rizin function discovery through `binlex-rizin` (and optionally `binlex-pdb`):

```bash
rizin -c 'aaa;aflj;' -q sample.dll | \
  binlex-symbols rizin | \
  binlex -i sample.dll --stdin | \
  jq 'select(.type == "function") | .address' | wc -l
```

`binlex-rizin` is also compatible with `radare2` JSON output.
