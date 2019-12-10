# lib-tcpdump-processing

A library designed to process `.pcapng` tcpdump trace file and extract SRT packets of interest for further analysis.

Currently, only `.pcapng` trace file captured at the receiver side containing only one flow of data is supported. For more complicated use cases, adjustments will be required.

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
venv/bin/extract-packets --help
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

To use the following scripts, please install the library first (see Sec. "Install the library with pip").

## `extract-packets`

This script parses `.pcapng` tcpdump trace file captured at a receiver side, saves the output in `.csv` format nearby the original file, extracts packets of interest and saves the obtained dataframe in `.csv` format nearby the original file.

Usage: 
```
venv/bin/extract-packets [OPTIONS] PATH
```
where `PATH` refers to `.pcapng` tcpdump trace file.

Options:
```
Options:
  --type [srt|data|probing|umsg_ack]
                                  Packet type to extract: SRT (both DATA and
                                  CONTROL), SRT DATA, SRT DATA probing, or SRT
                                  CONTROL UMSG_ACK packets.  [default:
                                  probing]
  --overwrite / --no-overwrite    If exists, overwrite the .csv file produced
                                  out of the .pcapng tcpdump trace one at the
                                  previous iterations of running the script.
                                  [default: False]
  --save / --no-save              Save dataframe with extracted packets into
                                  .csv file.  [default: False]
  --help                          Show this message and exit.
```

## `get-traffic-stats`

This script parses `.pcapng` network trace file,  and prints SRT-related traffic statistics, in particular, the overhead of SRT protocol in the transmission. Intermediate data is stored in  `.csv` format nearby the original file.

Usage: 
```
venv/bin/get-traffic-stats [OPTIONS] PATH
```
where `PATH` refers to `.pcapng` tcpdump trace file.

Options:
```
  --overwrite / --no-overwrite  If exists, overwrite the .csv file produced
                                out of the .pcapng tcpdump trace one at the
                                previous iterations of running the script.
                                [default: False]
  --help                        Show this message and exit.
```

Example output:

```
SRT Data payload:          6.685 Mbps
SRT Data overhead:         1.824%
SRT Data lost:             4.250%
SRT Data rexmit overhead:  8.857%
SRT ACK overhead:          0.404%
SRT ACKACK overhead:       0.404%
SRT NAK overhead:          0.161%
===========================================
SRT overall overhead:      9.630%
SRT Retransmitted:         8.699% of original packets
including:
    retransmitted twice:   3.706% of original packets
    retransmitted more:    0.372% of original packets
```

# Data Preparation

`.pcapng` tcpdump trace file with measurements from a certain network interface and port collected at the receiver side is used as a proxy for packets data collected within the protocol. This trace file is further preprocessed in a `.csv` format with timestamp, source IP address, destination IP address, protocol, and other columns and rows representing observations (received packets). 

This data is further cleaned and transformed using [pandas](https://pandas.pydata.org/) in the following way: 
1. The data is filtered to extract SRT packets only (`ws.protocol == SRT`) which make sense for further analysis. 
2. The dataset then is splitted into DATA (`srt.iscontrol == 0`) and CONTROL (`srt.iscontrol == 1`) packets.
3. For DATA packets , timestamps’ adjustments are done to convert the time from seconds to microseconds using the same procedure as in the protocol. To be precise, the new variable `ws.time.us` is obtained as `(ws.time * 1000000).astype('int64')`.
4. For DATA packets, the inter-arrival time is calculated as the difference between current and previous packet timestamps and stored as a separate variable `ws.iat.us`. Please note that the time delta for the first SRT data packet by default is equal to 0, that's why this packet might probably should be excluded from the analysis.
5. The type conversion is performed to structure the data in appropriate formats.

The detailed description of dataset variables, Wireshark dissectors and other data is provided in table below. See columns `DATA` and `CONTROL` to check whether the variable is present (`✓`) or absent (`-`) in a corresponding dataset.

| Dataset Variable  | Wireshark Dissector    | Description                                                | DATA       | CONTROL   | Data Type  |
|:------------------|:-----------------------|:-----------------------------------------------------------|:-----------|:----------|:-----------|
| ws.no             | _ws.col.No.            | Number as registered by Wireshark                          | ✓          | ✓         | int64      |
| ws.time           | _ws.col.Time           | Timestamp as registered by Wireshark (seconds)             | ✓          | ✓         | float64    |
| ws.source         | _ws.col.Source         | Source IP address                                          | ✓          | ✓         | category   |
| ws.destination    | _ws.col.Destination    | Destination IP address                                     | ✓          | ✓         | category   |
| ws.protocol       | _ws.col.Protocol       | Protocol                                                   | ✓          | ✓         | category   |
| ws.length         | _ws.col.Length         | Length (bytes)                                             | ✓          | ✓         | int16      |
| ws.info           | _ws.col.Info           | Information                                                | ✓          | ✓         | object     |
| udp.length        | udp.length             | UDP packet size (bytes)                                    | ✓          | ✓         | int16      |
| srt.iscontrol     | srt.iscontrol          | Content type (CONTROL if 1, DATA if 0)                     | ✓          | ✓         | int8       |
| srt.type          | srt.type               | Message type (e.g. UMSG_ACK, UMSG_ACKACK)                  | -          | ✓         | category   |
| srt.seqno         | srt.seqno              | Sequence number                                            | ✓          | -         | int64      |
| srt.msg.rexmit    | srt.msg.rexmit         | Sent as original if 0, retransmitted if 1                  | ✓          | -         | int8       |
| srt.timestamp     | srt.timestamp          | Timestamp since the socket was opened (microseconds)       | ✓          | ✓         | int64      |
| srt.id            | srt.id                 | Destination socket id                                      | ✓          | ✓         | category   |
| srt.ack_seqno     | srt.ack_seqno          | First unacknowledged sequence number                       | -          | ✓         | int64      |
| srt.rate          | srt.rate               | Receiving speed estimation (packets/s)                     | -          | ✓         | int64      |
| srt.bw            | srt.bw                 | Bandwidth estimation (packets/s)                           | -          | ✓         | int64      |
| srt.rcvrate       | srt.rcvrate            | Receiving speed estimation (bytes/s)                       | -          | ✓         | int64      |
| data.len          | data.len               | Payload size or 0 in case of control packets (bytes)       | ✓          | -         | int16      |
| ws.time.us        | -                      | Timestamp as registered by Wireshark (microseconds)        | ✓          | -         | int64      |
| ws.iat.us         | -                      | Packet inter-arrival time (microseconds)                   | ✓          | -         | int64      |

## Probing DATA Packets

Probing DATA packets are extracted from the DATA packets dataset as follows:
1. Find all the packet pairs where the latest 4 bits of their sequence numbers (`srt.seqno`) are `0000` and `0001`. The order is important.
2. For each packet pair, check whether both of packets are sent as `Original` (`srt.msg.rexmit` == 0), not `Retransmitted` (`srt.msg.rexmit` == 1).
3. For the remain packet pairs, take the packet with sequence number ending with `0001` bits as probing packet.

Here is an example of packet pair where `Frame 25` corresponds to the probing packet
```
Frame 24: 1514 bytes on wire (12112 bits), 1500 bytes captured (12000 bits) on interface 0
Ethernet II, Src: 12:34:56:78:9a:bc (12:34:56:78:9a:bc), Dst: Microsof_59:95:17 (00:0d:3a:59:95:17)
Internet Protocol Version 4, Src: 51.144.160.127, Dst: 10.1.4.4
User Datagram Protocol, Src Port: 60900, Dst Port: 4200
SRT Protocol
    0... .... .... .... .... .... .... .... = Content: DATA
    .111 1111 1110 0111 0111 1000 0011 0000 = Sequence Number: 2145876016
    11.. .... .... .... .... .... .... .... = Packet Boundary: PB_SOLO (3)
    ..0. .... .... .... .... .... .... .... = In-Order Indicator: 0
    ...0 0... .... .... .... .... .... .... = Encryption Status: Not encrypted (0)
    .... .0.. .... .... .... .... .... .... = Sent as: Original
    .... ..00 0000 0000 0000 0000 0001 0001 = Message Number: 17
    Time Stamp: 449263 (0x0006daef)
    Destination Socket ID: 0x1c9ff5e1
    Data (1442 bytes)

```

```
Frame 25: 1514 bytes on wire (12112 bits), 1500 bytes captured (12000 bits) on interface 0
Ethernet II, Src: 12:34:56:78:9a:bc (12:34:56:78:9a:bc), Dst: Microsof_59:95:17 (00:0d:3a:59:95:17)
Internet Protocol Version 4, Src: 51.144.160.127, Dst: 10.1.4.4
User Datagram Protocol, Src Port: 60900, Dst Port: 4200
SRT Protocol
    0... .... .... .... .... .... .... .... = Content: DATA
    .111 1111 1110 0111 0111 1000 0011 0001 = Sequence Number: 2145876017
    11.. .... .... .... .... .... .... .... = Packet Boundary: PB_SOLO (3)
    ..0. .... .... .... .... .... .... .... = In-Order Indicator: 0
    ...0 0... .... .... .... .... .... .... = Encryption Status: Not encrypted (0)
    .... .0.. .... .... .... .... .... .... = Sent as: Original
    .... ..00 0000 0000 0000 0000 0001 0010 = Message Number: 18
    Time Stamp: 449292 (0x0006db0c)
    Destination Socket ID: 0x1c9ff5e1
    Data (1442 bytes)
```

## UMSG_ACK CONTROL Packets

UMSG_ACK CONTROL packets are extracted from the CONTROL packets dataset as follows: 
1. Find all the packets with `srt.type == 0x00000002`.
2. Drop rows with `NaN` values of `srt.rate`, `srt.bw`, and `srt.rcvrate` variables (so called light acknowledgements).

# ToDo

1. Investigate the problem with possible missing data. It’s well-known issue that at high bitrates tshark may skip the data, there should be something to check this (tshark logs, etc.) and then perform missing data imputation.
2. Investigate the topic with time needed for SRT library to receive and process the packet. This time should be taken into account and tcpdump timestamps may require additional adjustments.
3. Investigate the case with zero packet inter-arrival time, some adjustments might be required.