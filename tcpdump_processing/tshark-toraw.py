# tshark -r "/Users/maxsharabayko/projects/srt/bugs/obs-mxd-1223/ffmpeg-interop-mxd-srt-125ms-export.pcap" --disable-protocol udt -Y srt -T fields -e data.data -E separator=;

import binascii
import sys
string = open(sys.argv[1],'r').read()
sys.stdout.write(binascii.unhexlify(string)) # needs to be stdout.write to avoid trailing newline