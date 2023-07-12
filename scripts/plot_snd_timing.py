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


pd.options.mode.chained_assignment = None  # default='warn'


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
	help=	'If exists, overwrite the .csv file produced out of the .pcap(ng) one '
			'at the previous iterations of running the script.',
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
			'This option is helpful when there is no SRT handshake in .pcap(ng) file. '
			'Should be used together with --overwrite option.'
)
@click.option(
	'--latency',
	help=	'SRT latency, in milliseconds, to plot on a graph.'
)
def main(path, overwrite, with_rexmits, port, latency):
	"""
	This script parses .pcap(ng) tcpdump trace file captured at the sender side
	and plots the time delta between SRT packet timestamp (srt.timestamp) and
	packet time captured by Wireshark at the sender side (ws.time).
	This could be done for either SRT original DATA packets only, or both
	original and retransmitted DATA packets.
	"""
	pcap_filepath = pathlib.Path(path)
	if port is not None:
		csv_filepath = convert_to_csv(pcap_filepath, overwrite, True, port)
	else:
		csv_filepath = convert_to_csv(pcap_filepath, overwrite)
	
	try:
		srt_packets = extract_srt_packets(csv_filepath)
	except (UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound) as error:
		print(f'{error}')
		return
	
	index = SRTDataIndex(srt_packets)
	df = srt_packets[index.data_pkts]
	df['delta'] = df['ws.time'] * 1000 - df['srt.timestamp'] / 1000
	# NOTE: The correction on the very first DATA packet is made by means of subtracting
	# respective time delta from all the whole column.
	df['delta'] = df['delta'] - df['delta'].iloc[0]
	org = df[df['srt.msg.rexmit'] == 0]
	rxt = df[df['srt.msg.rexmit'] == 1]

	ax1 = org.plot.scatter(x = 'ws.time', xlabel = 'Time, s', y = 'delta', ylabel = 'Time Delta, ms', label='Original')
	if with_rexmits:
		rxt.plot(x = 'ws.time', xlabel = 'Time, s', y = 'delta', ylabel = 'Time Delta, ms', kind='scatter', color='r', label='Retransmitted', ax=ax1)
	if latency:
		plt.axhline(float(latency), color='g')
		plt.text(1, float(latency) + 0.05,'SRT latency', color='g')
	plt.show()


if __name__ == '__main__':
	main()
