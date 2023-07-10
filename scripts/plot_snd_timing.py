"""
Script designed to plot delta between packet capture time (Wireshark) and
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
	# TODO: rcv side?
	"""
	This script parses .pcap or .pcapng tcpdump trace file captured at the receiver side (preferably), 
	and plots time delta between SRT packet timestamp and packet arrival time captured by Wireshark.
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

	df['Delta'] = df['Delta'] - df['Delta'].iloc[0]

	print(df[['ws.time', 'srt.timestamp', 'Delta']])
	# return
	
	#print(df[(df['Delta'] > 200000) & (df['ws.no'] > 165730)])
	ax1 = df.plot.scatter(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'TS Delta, µs')


	if with_rexmits:
		df_rxt = srt_packets[index.data_pkts_rxt]
		print(df_rxt[['ws.time', 'srt.timestamp']])

		df_rxt['Delta'] = df_rxt['ws.time'] * 1000000 - df_rxt['srt.timestamp']
		print(df_rxt[['ws.time', 'srt.timestamp', 'Delta']])

		df_rxt['Delta'] = df_rxt['Delta'] - df_rxt['Delta'].iloc[0]
		print(df_rxt[['ws.time', 'srt.timestamp', 'Delta']])

		df_rxt.plot(x = 'ws.time', xlabel = 'Time, s', y = 'Delta', ylabel = 'TS Delta, µs', kind='scatter',color='r', ax=ax1)
	plt.show()


if __name__ == '__main__':
	main()