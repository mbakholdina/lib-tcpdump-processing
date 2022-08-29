"""
Script designed to collect and output network traffic statistics.
"""
import pathlib

import click
import pandas as pd
import matplotlib.pyplot as plt

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


class SRTDataIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts = (srt_packets['srt.iscontrol'] == 1)
		self.ack_pkts = (srt_packets['srt.type'] == 2)
		self.data_pkts = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)


@click.command()
@click.argument(
	'path', 
	type=click.Path(exists=True)
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcap (or .pcapng) '
			'tcpdump trace one at the previous iterations of running the script.',
	show_default=True
)
def main(path, overwrite):
	"""
	This script parses .pcap or .pcapng tcpdump trace file captured at the receiver side, 
	collects and outputs network traffic statistics.
	"""
	# Process tcpdump trace file and get SRT data packets only
	# (either all data packets or probing packets only)
	pcapng_filepath   = pathlib.Path(path)
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

	df = srt_packets
	print(srt_packets['srt.bufavail'].dropna())
	

	#df['Delta'] = df['ws.time'] * 1000000 - df['srt.timestamp']
	fig, (ax1, ax2) = plt.subplots(1, 2)
	ax1 = df.plot.scatter(x = 'ws.time', y = 'srt.bufavail')
	ax2 = df.plot.scatter(x = 'ws.time', y = 'srt.rtt')
	plt.show()



if __name__ == '__main__':
	main()