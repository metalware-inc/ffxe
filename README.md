# FFXE

FFXE is a CFG recovery tool for Cortex-M based embedded firmware binaries.

It was first presented at USENIX 2024 in [_FFXE: Dynamic Control Flow Graph Recovery for Embedded Firmware Binaries_](https://www.usenix.org/conference/usenixsecurity24/presentation/tsang) as a way to recover indirect calls to asynchronously-registered interrupt handler functions using dynamic forced execution.
For citation and reading, please refer to the [author revision](https://rctsang.github.io/publications/usenix24-ffxe/ffxe-revision.pdf), which corrects a reporting inaccuracy in the case study.
The original artifacts have been saved and can be found [in this fork](https://github.com/aseec-lab/ffxe-usenix24).

While it is still not an official package, this repository has been cleaned up to make it a bit easier to use in other projects, and as such it no longer contains the evaluation scripts and tools. To find those, you can checkout commit [17adcd8](https://github.com/rchtsang/ffxe/tree/17adcd8) or go to the aforementioned fork.

## Setup

### Native

The dependencies can be installed in a conda environment using the provided `environment.yml` file.

_After activating the environment, the engine should be installed via pip in developer mode with `pip install -e .` from the project root directory_.


