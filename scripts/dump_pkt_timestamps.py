"""
The script dumps SRT timestamps (not Wireshark ws.time) of SRT data packet to a CSV file
to be used by srt-xtransmit with the --playback-csv argument.
"""
import pathlib

import click
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


class SRTDataIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts        = (srt_packets['srt.iscontrol'] == 1)
		self.data_pkts = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)


@click.command()
@click.argument(
	'input', 
	help= 'The pcap file to use as an input.',
	type=click.Path(exists=True)
)
@click.argument(
	'output',
	help= 'The output CSV file to be produced.',
	type=click.Path(exists=False)
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcap (or .pcapng) '
			'tcpdump trace one at the previous iterations of running the script.',
	show_default=True
)
def main(input, output, overwrite):
	"""
	This script parses .pcap or .pcapng tcpdump trace file
	and outputs all original data packet SRT timestamps (not Wireshark capture time) into a CSV file.
	"""
	# Process tcpdump trace file and get SRT data packets only
	# (either all data packets or probing packets only)
	pcapng_filepath   = pathlib.Path(input)
	csv_filepath      = convert.convert_to_csv(pcapng_filepath, overwrite)
	
	try:
		srt_packets = extract_packets.extract_srt_packets(csv_filepath)
	except extract_packets.UnexpectedColumnsNumber as error:
		print(
			f'Exception captured: {error} '
			'Please try running the script with --overwrite option.'
		)
		return

	if srt_packets.empty:
		print("No SRT packets found.")
		return
		
	index = SRTDataIndex(srt_packets)	
	df = srt_packets[index.data_pkts_org]
	(df['srt.timestamp'] / 1000000.0).to_csv(output, index=False)
	
	# TODO: Plotting the histogram of packets by 10 ms bins.
	# The code below is missing the end time in the arrange() function.
	#x = np.arange(0, 27, 0.01, dtype = float)
	#fig, axis = plt.subplots(figsize =(10, 5))
	#axis.hist((df['srt.timestamp'] / 1000000.0), bins = x)
	#plt.show()

	return


if __name__ == '__main__':
	main()
