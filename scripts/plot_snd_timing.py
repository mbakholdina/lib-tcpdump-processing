"""
Script designed to plot time delta between packet capture time (Wireshark) and
SRT packet timestamp.
"""
import pathlib

import click
import pandas as pd
import matplotlib.pyplot as plt

from tcpdump_processing.convert import convert_to_csv
from tcpdump_processing.extract_packets import extract_srt_packets, UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound


class SRTDataIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts		= (srt_packets['srt.iscontrol'] == 1)
		self.data_pkts		= (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org	= self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)
		self.data_pkts_rxt	= self.data_pkts & (srt_packets['srt.msg.rexmit'] == 1)


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
	help=	'Also show retransmitted data packets.',
	show_default=True
)
@click.option(
	'--port',
	help=	'Decode packets as SRT on a specified port. '
			'This option is helpful when there is no SRT handshake in .pcap(ng) file.',
)
def main(path, overwrite, with_rexmits, port):
	"""
	This script parses .pcap(ng) tcpdump trace file captured at the sender side
	and plots the time delta between SRT packet timestamp (srt.timestamp) and
	packet time captured by Wireshark at the sender side (ws.time).
	This could be done for either SRT original DATA packets only, or both
	original and retransmitted DATA packets.
	"""
	# Convert .pcap(ng) to .csv tcpdump trace file
	pcap_filepath = pathlib.Path(path)
	if port is not None:
		csv_filepath = convert_to_csv(pcap_filepath, overwrite, True, port)
	else:
		csv_filepath = convert_to_csv(pcap_filepath, overwrite)
	
	# Extract SRT packets
	try:
		srt_packets = extract_srt_packets(csv_filepath)
	except (UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound) as error:
		print(f'{error}')
		return
		
	index = SRTDataIndex(srt_packets)
	print(srt_packets[['ws.time', 'srt.timestamp']])
	df = srt_packets[index.data_pkts_org]
	df['Delta'] = df['ws.time'] * 1000000 - df['srt.timestamp']
	print(df[['ws.time', 'srt.timestamp', 'Delta']])
	# NOTE: The correction on the very first DATA packet is made by means of subtracting
	# respective time delta from all the whole column.
	df['Delta'] = df['Delta'] - df['Delta'].iloc[0]
	print(df[['ws.time', 'srt.timestamp', 'Delta']])
	
	ax1 = df.plot.scatter(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'Time Delta, µs', label='Original')

	if with_rexmits:
		df_rxt = srt_packets[index.data_pkts_rxt]
		print(df_rxt[['ws.time', 'srt.timestamp']])
		df_rxt['Delta'] = df_rxt['ws.time'] * 1000000 - df_rxt['srt.timestamp']
		print(df_rxt[['ws.time', 'srt.timestamp', 'Delta']])
		df_rxt['Delta'] = df_rxt['Delta'] - df_rxt['Delta'].iloc[0]
		print(df_rxt[['ws.time', 'srt.timestamp', 'Delta']])

		df_rxt.plot(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'Time Delta, µs', kind='scatter', color='r', label='Retransmitted', ax=ax1)

	plt.show()


if __name__ == '__main__':
	main()