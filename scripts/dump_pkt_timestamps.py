"""
The script dumps SRT timestamps (not Wireshark ws.time) of SRT data packets to a .csv file
to be used by srt-xtransmit application with the --playback-csv argument.
"""
import pathlib

import click

from tcpdump_processing.convert import convert_to_csv
from tcpdump_processing.extract_packets import extract_srt_packets, UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound


class SRTDataIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts        = (srt_packets['srt.iscontrol'] == 1)
		self.data_pkts = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)


@click.command()
@click.argument(
	'input', 
	type=click.Path(exists=True)
)
@click.argument(
	'output',
	type=click.Path(exists=False)
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcap(ng) '
			'one at the previous iterations of running the script.',
	show_default=True
)
@click.option(
	'--port',
	help=	'Decode packets as SRT on a specified port. '
			'This option is helpful when there is no SRT handshake in .pcap(ng) file. '
			'Should be used together with --overwrite option.'
)
def main(input, output, overwrite, port):
	"""
	This script parses .pcap(ng) tcpdump trace file and outputs all original
	data packets' SRT timestamps (not Wireshark ws.time) into a .csv file.

	INPUT is the .pcap(ng) file to use as an input.

	OUTPUT is the output .csv file to be produced.
	"""
	pcap_filepath = pathlib.Path(input)
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
	df = srt_packets[index.data_pkts_org]
	(df['srt.timestamp'] / 1000000.0).to_csv(output, index=False, header=False)
	
	# TODO: Plotting the histogram of packets by 10 ms bins.
	# The code below is missing the end time in the arrange() function.
	#x = np.arange(0, 27, 0.01, dtype = float)
	#fig, axis = plt.subplots(figsize =(10, 5))
	#axis.hist((df['srt.timestamp'] / 1000000.0), bins = x)
	#plt.show()

	return


if __name__ == '__main__':
	main()
