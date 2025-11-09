# R4i Kernel Patcher
This tool patches the kernel of R4i cards from r4i-sdhc.com disabling the anti-tamper checks.
Using this allows any modifications to be done to R4.dat without the card hanging on boot or preventing certain games to load.

## Extra patches
This tool also comes with some extra patches inside `patch_settings.json` that can be disabled or edited at will:
- **Disable fake card check**: Allows for cards from other websites to work with this kernel.
- **Disable malicious infinite loops**: Some places of the code are meant to hang the card if certain checks aren't correct, this only happens with cards from other websites.
- **Disable upgrade firmware check**: Allows cards with an outdated flash to work without needing to upgrade.
- **Disable loader CRC verification**: Allows modified loaders to be accepted by the kernel.

## Requirements
- .NET 8.0 Runtime

## Usage
Place R4.dat in the same folder as the tool executable and run the following command:
`./"R4i Kernel Patcher.exe" <input_file> <output_file>` example: `./"R4i Kernel Patcher.exe" R4.dat R4_patched.dat`