"""
Script designed to plot delta between packet capture time (Wireshark) and
SRT packet timestamp.
"""
import pathlib

import click
import pandas as pd
import matplotlib.pyplot as plt

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


class SRTDataIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts        = (srt_packets['srt.iscontrol'] == 1)
		self.data_pkts = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)
		self.data_pkts_rxt = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 1)


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
@click.option(
	'--with-rexmits/--without-rexmits',
	default=False,
	help=	'Also show also retransmitted data packets.',
	show_default=True
)
def main(path, overwrite, with_rexmits):
	"""
	This script parses .pcap or .pcapng tcpdump trace file captured at the receiver side (preferably), 
	and plots time delta between SRT packet timestamp and packet arrival time captured by Wireshark.
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
	#print(srt_packets[index.data_pkts_org])
	
	df = srt_packets[index.data_pkts_org]
	df['Delta'] = df['ws.time'] * 1000000 - df['srt.timestamp']
	
	#print(df[(df['Delta'] > 200000) & (df['ws.no'] > 165730)])
	ax1 = df.plot.scatter(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'TS Delta, µs')
	if with_rexmits:
		df_rxt = srt_packets[index.data_pkts_rxt]
		df_rxt['Delta'] = df_rxt['ws.time'] * 1000000 - df_rxt['srt.timestamp']
		df_rxt.plot(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'TS Delta, µs', kind='scatter',color='r', ax=ax1)
	plt.show()


if __name__ == '__main__':
	main()