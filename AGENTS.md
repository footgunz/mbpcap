# mbpcap - a serial capture tool

##  Overview
This is a capture tool designed to frame and capture data from a serial port as "packets" and record them in a pcap formatted file for use with Wireshark or other pcap processing tools.

This program is completely inspired by the Open Source `bacnet-stack`'s `mstpcap` tool which is written in C and does a similar type of capture, but specific to BACnet

This program will be written in Go if possible

## Capture Format
- Implement the most minimal possible PCAP initially - set the timestamp, data, and the minimum number of required fields needed for a valid "capture" file to open in Wireshark/TShark
- Input should be serial port, baud rate, data bits,parity, stop bits, and output file.  Use 115200/8/none/1 by default for the serial parameters
- While `mstpcap` supports being used as a wireshark plugin / pipe, that is out of scope for the initial development, unless it is __completely trivial__
- `mstpcap` has BACnet specific options related to token processing, as it is a token passing protocol.  We don't need that

## References
`bacnet-stack` - https://github.com/bacnet-stack/bacnet-stack
`mstpcap` tool - https://github.com/bacnet-stack/bacnet-stack/tree/master/apps/mstpcap



