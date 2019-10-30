A library to process `.pcapng` tcpdump trace file and extract SRT packets of interest for further analysis.

Currently, only .pcapng trace file captured at a receiver side containing only one flow of data is supported. For more complicated use cases, adjustments will be required.

# Getting Started

## Requirements

* python 3.6+

## Install the library with pip

For development, it is recommended 
* To use `venv` for virtual environments and `pip` for installing the library and any dependencies. This ensures the code and dependencies are isolated from the system Python installation,
* To install the library in “editable” mode by running from the same directory `pip install -e .`. This lets changing the source code (both tests and library) and rerunning tests against library code at will. For regular installation, use `pip install .`.

As soon as the library is installed, you can run modules directly
```
venv/bin/python -m tcpdump_processing.extract_packets --help
```

or use preinstalled executable scripts
```
venv/bin/extract_packets --help
```

## Install the library to import in another project

Install with pip (a venv is recommended), using pip's VCS requirement specifier
```
pip install 'git+https://github.com/mbakholdina/lib-tcpdump-processing.git@v0.1#egg=tcpdump_processing'
```

or simply put the following row in `requirements.txt`
```
git+https://github.com/mbakholdina/lib-tcpdump-processing.git@v0.1#egg=tcpdump_processing
```

Remember to quote the full URL to avoid shell expansion in case of direct installation.

This installs the version corresponding to the git tag 'v0.1'. You can replace that with a branch name, a commit hash, or a git ref as necessary. See the [pip documentation](https://pip.pypa.io/en/stable/reference/pip_install/#vcs-support) for details.

As soon as the library is installed, you can import the whole library
```
import tcpdump_processing
```

or a particular module
```
import tcpdump_processing.extract_packets as extract_packets
```

# Executable Scripts

## `extract_packets`

This script parses .pcapng tcpdump trace file captured at a receiver side, saves the output in .csv format nearby the original file, extract packets of interest and saves the obtained dataframe in .csv format nearby the original file.

Usage: 
```
extract_packets [OPTIONS] PATH
```

Options:
```
--type [srt|data|probing|umsg_ack]
                                Packet type to extract: SRT (both DATA and
                                CONTROL), SRT DATA, SRT DATA probing, or SRT
                                CONTROL UMSG_ACK packets.
--save / --no-save              Save dataframe with extracted packets into
                                .csv file.
--help                          Show this message and exit.
```