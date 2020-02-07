"""
Module designed to extract packets of interest (srt, data, probing, 
umsg_ack) out of the .pcapng tcpdump trace file. Currently only .pcapng
file captured at a receiver side and one data flow are supported.
"""

import enum
import pathlib

import click
import pandas as pd

import tcpdump_processing.convert as convert


class AutoName(enum.Enum):
	def _generate_next_value_(name, start, count, last_values):
		return name


@enum.unique
class PacketTypes(AutoName):
	srt = enum.auto()
	data = enum.auto()
	probing = enum.auto()
	umsg_ack = enum.auto()


PACKET_TYPES = [name for name, member in PacketTypes.__members__.items()]


class UnexpectedColumnsNumber(Exception):
	pass


def extract_srt_packets(filepath: pathlib.Path) -> pd.DataFrame:
	""" 
	Extract SRT packets (both DATA and CONTROL) from the .csv
	tcpdump trace file. 

	Attributes:
		filepath: 
			:class:`pathlib.Path` path to the .csv tcpdump trace file.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT packets or 
		an empty dataframe if there is no SRT packets.

	Raises:
		:exc:`convert.FileDoesNotExist` 
			if `filepath` file does not exist.
		:exc: `UnexpectedColumnsNumber`
			if the .csv tcpdump trace file contains unexpected 
			number of columns.
	"""
	if not filepath.exists():
		raise convert.FileDoesNotExist(filepath)

	columns = [
		'_ws.col.No.',
		'frame.time',
		'_ws.col.Time',
		'_ws.col.Source',
		'_ws.col.Destination',
		'_ws.col.Protocol',
		'_ws.col.Length',
		'_ws.col.Info',
		'udp.length',
		'srt.iscontrol',
		'srt.type',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'srt.ack_seqno',
		'srt.rate',
		'srt.bw',
		'srt.rcvrate',
		'data.len',
	]

	types = [
		'int64',		# _ws.col.No. (ws.no)
		'object',		# frame.time
		'float64',		# _ws.col.Time (ws.time)
		'category',		# _ws.col.Source (ws.source)
		'category',		# _ws.col.Destination (ws.destination)
		'category',		# _ws.col.Protocol (ws.protocol)
		'int16',		# _ws.col.Length (ws.length)
		'object',		# _ws.col.Info (ws.info)
		'float16',		# udp.length
		'float16',		# srt.iscontrol
		'category',		# srt.type
		'float64',		# srt.seqno
		'float16',		# srt.msg.rexmit
		'float64',		# srt.timestamp
		'category',		# srt.id
		'float64',		# srt.ack_seqno
		'float64',		# srt.rate
		'float64',		# srt.bw
		'float64',		# srt.rcvrate
		'float16'		# data.len
	]

	columns_types = dict(zip(columns, types))
	packets = pd.read_csv(filepath, sep=';', dtype=columns_types)

	if len(packets.columns) != 20:
		raise UnexpectedColumnsNumber(f'Unexpected columns number in .csv file: {filepath}.')

	packets.columns = [
		'ws.no',
		'frame.time',
		'ws.time',
		'ws.source',
		'ws.destination',
		'ws.protocol',
		'ws.length',
		'ws.info',
		'udp.length',
		'srt.iscontrol',
		'srt.type',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'srt.ack_seqno',
		'srt.rate',
		'srt.bw',
		'srt.rcvrate',
		'data.len'
	]

	# It's either a dataframe with SRT only packets or an empty dataframe
	# if there is no SRT packets in packets dataframe
	srt_packets = packets[packets['ws.protocol'] == 'SRT'].copy()
	srt_packets['frame.time'] = pd.to_datetime(srt_packets['frame.time'])
	srt_packets['srt.iscontrol'] = srt_packets['srt.iscontrol'].astype('int8')
	srt_packets['srt.timestamp'] = srt_packets['srt.timestamp'].astype('int64')
	srt_packets['udp.length'] = srt_packets['udp.length'].fillna(0).astype('int16')
	srt_packets['data.len'] = srt_packets['data.len'].fillna(0).astype('int16')

	return srt_packets


def extract_data_packets(srt_packets: pd.DataFrame) -> pd.DataFrame:
	""" 
	Extract SRT DATA packets from SRT packets (both DATA and CONTROL)
	`srt_packets` dataframe. 
	
	Attributes:
		srt_packets: 
			:class:`pd.DataFrame` dataframe with SRT packets (both DATA and 
			CONTROL) obtained from the .csv tcpdump trace file using
			`extract_srt_packets` function.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT DATA packets or
		an empty dataframe if there is no DATA packets found.
	"""
	columns = [
		'ws.no',
		'frame.time',
		'ws.time',
		'ws.source',
		'ws.destination',
		'ws.protocol',
		'ws.length',
		'ws.info',
		'srt.iscontrol',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'data.len',
	]
	data = srt_packets.loc[srt_packets['srt.iscontrol'] == 0, columns]
	data['srt.seqno'] = data['srt.seqno'].astype('int64')
	data['srt.msg.rexmit'] = data['srt.msg.rexmit'].astype('int8')
	data['data.len'] = data['data.len'].astype('int16')

	# Group data by source, destination and socket id
	# NOTE: There should be only one group under the assumption that tcpdump
	# trace file has been taken at the receiver side and there is only one 
	# data flow. For more complicated use cases, a proper data splitting 
	# should be implemented.
	data_grouped = data.groupby(['ws.source', 'ws.destination', 'srt.id'])
	
	# Return an empty dataframe if there is no DATA packets found
	if len(data_grouped) == 0:
		columns += [
			'ws.time.us',
			'ws.iat.us'
		]
		return pd.DataFrame(columns=columns)

	# TODO: Implement
	# Return an empty dataframe if there is more than 1 data flow detected
	if len(data_grouped) > 1:
		print(
			'There are more than 1 data flow detected. '
			'This case is not supported. The groups found are listed below:'
		)

		for name, group in data_grouped:
			print(name)
			print(group)

		columns += [
			'ws.time.us',
			'ws.iat.us'
		]
		return pd.DataFrame(columns=columns)

	assert(len(data_grouped) == 1)

	# Calculate packet inter-arrival times
	# NOTE: Packet timestamp `ws.time` in tcpdump trace file is measured 
	# in seconds, time in SRT is measured in microseconds (us). 
	# That is why, first we multiply the timestamp by 1000000, then make 
	# a conversion from float to int as it is done in SRT, and only then 
	# calculate the inter-arrival times. The very first value will be NaN,
	# fillna() changes it to 0, otherwise astype() will fail. Finally,
	# we convert the type from float to int, because diff() returns float.
	# NOTE: In SRT protocol, the time delta for the first SRT data packet is
	# taken as the difference between time of this data packet and the
	# previous handshake one. Here we assume this value to be equal to 0
	# for simplicity.
	data['ws.time.us'] = (data['ws.time'] * 1000000).astype('int64')
	data['ws.iat.us'] = data['ws.time.us'].diff().fillna(0).astype('int64')

	return data


def extract_probing_packets(srt_packets: pd.DataFrame) -> pd.DataFrame:
	""" 
	Extract SRT probing DATA packets from SRT packets (both DATA and CONTROL)
	`srt_packets` dataframe. 
	
	Attributes:
		srt_packets: 
			:class:`pd.DataFrame` dataframe with SRT packets (both DATA and 
			CONTROL) obtained from the .csv tcpdump trace file using
			`extract_srt_packets` function.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT probing DATA packets or
		an empty dataframe if there is no probing packets found.
	"""
	data = extract_data_packets(srt_packets)

	# Apply logic AND to SRT data packet sequence number and 15 (1111) in order to check
	# the latest 4 bits of the sequence number (whether it is 0000=0 or 0001=1).
	# 0001=1 corresponds to the probing packet.
	data['seqno'] = data['srt.seqno'] & 15
	# Shift seqno column by 1 in order to get the current and previous values nearby.
	# We are looking for pairs: probing packet (0001=1) and previous packet (0000=0).
	# The order is important. Fill the first NA value with 1 in order to exclude this
	# row for sure.
	data['seqno_shifted'] = data['seqno'].shift().fillna(1).astype('int64')
	# Then we are interested in those probing packets for which packet pairs consist
	# of original only packets. There should be no retransmitted packets.
	# Shift srt.msg.rexmit column by 1 to get the current and previous values of rexmit
	# flag (0 - original packet, 1 - retransmitted packet) nearby. Fill the first
	# NA value with 1 in order to exclude this row for sure.
	data['rexmit_shifted'] = data['srt.msg.rexmit'].shift().fillna(1).astype('int8')

	probing_packets = data[
		(data['seqno'] == 1) & 
		(data['seqno_shifted'] == 0) & 
		(data['srt.msg.rexmit'] == 0) & 
		(data['rexmit_shifted'] == 0)
	]
	
	columns = [
		'ws.no',
		'frame.time',
		'ws.time',
		'ws.source',
		'ws.destination',
		'ws.protocol',
		'ws.length',
		'ws.info',
		'srt.iscontrol',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'data.len',
		'ws.time.us',
		'ws.iat.us',
	]
	probing_packets = probing_packets[columns]

	return probing_packets


def extract_umsg_ack_packets(srt_packets: pd.DataFrame) -> pd.DataFrame:
	""" 
	Extract SRT UMSG_ACK CONTROL packets from SRT packets (both DATA and CONTROL)
	`srt_packets` dataframe. 
	
	Attributes:
		srt_packets: 
			:class:`pd.DataFrame` dataframe with SRT packets (both DATA and 
			CONTROL) obtained from the .csv tcpdump trace file using
			`extract_srt_packets` function.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT UMSG_ACK CONTROL packets or
		an empty dataframe if there is no UMSG_ACK packets found.
	"""
	columns = [
		'ws.no',
		'frame.time',
		'ws.time',
		'ws.source',
		'ws.destination',
		'ws.protocol',
		'ws.length',
		'ws.info',
		'srt.iscontrol',
		'srt.type',
		'srt.timestamp',
		'srt.id',
		'srt.ack_seqno',
		'srt.rate',
		'srt.bw',
		'srt.rcvrate',
	]
	control = srt_packets.loc[srt_packets['srt.iscontrol'] == 1, columns]

	# Group data by source, destination, socket id and packet type
	grouped = control.groupby(['ws.source', 'ws.destination', 'srt.id', 'srt.type'])
	# Find the group with packet type = UMSG_ACK ('0x00000002')
	# NOTE: There should be only one group under the assumption that tcpdump
	# trace file has been taken at the receiver side and there is only one 
	# data flow. For more complicated use cases, a proper data splitting 
	# should be implemented.
	names = [name for name, _ in grouped if name[len(name) - 1] == '0x00000002']

	# Return an empty dataframe if there is no UMSG_ACK packets found
	if len(names) == 0:
		return pd.DataFrame(columns=columns)

	# TODO: Implement
	# Return an empty dataframe if there is more than 1 data flow detected
	if len(names) > 1:
		print(
			'There are more than 1 data flow detected. '
			f'This case is not supported. The groups found are listed below:'
		)

		for name in names:
			print(name)

		return pd.DataFrame(columns=columns)
 
	assert(len(names) == 1)

	umsg_ack = grouped.get_group(names[0])

	# Drop rows with NaN values in srt.rate, srt.bw, srt.rcvrate columns 
	# (so called light acknowledgements)
	umsg_ack = umsg_ack.dropna(subset=['srt.rate', 'srt.bw', 'srt.rcvrate'], how='any')

	# Convert types
	umsg_ack['srt.ack_seqno'] = umsg_ack['srt.ack_seqno'].astype('int64')
	umsg_ack['srt.rate'] = umsg_ack['srt.rate'].astype('int64')
	umsg_ack['srt.bw'] = umsg_ack['srt.bw'].astype('int64')
	umsg_ack['srt.rcvrate'] = umsg_ack['srt.rcvrate'].astype('int64')

	return umsg_ack


@click.command()
@click.argument(
	'path', 
	type=click.Path(exists=True)
)
@click.option(
	'--type',
	type=click.Choice(PACKET_TYPES),
	default=PacketTypes.probing.value,
	help=	'Packet type to extract: SRT (both DATA and CONTROL), SRT DATA, '
			'SRT DATA probing, or SRT CONTROL UMSG_ACK packets.',
	show_default=True
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcapng '
			'tcpdump trace one at the previous iterations of running the script.',
	show_default=True
)
@click.option(
	'--save/--no-save',
	default=False,
	help='Save dataframe with extracted packets into .csv file.',
	show_default=True
)
def main(path, type, overwrite, save):
	"""
	This script parses .pcapng tcpdump trace file captured at a receiver side,
	saves the output in .csv format nearby the original file, extract packets 
	of interest and saves the obtained dataframe in .csv format nearby the 
	original file.
	"""
	# Convert .pcapng to .csv tcpdump trace file
	pcapng_filepath = pathlib.Path(path)	
	csv_filepath = convert.convert_to_csv(pcapng_filepath, overwrite)

	# Extract packets of interest
	try:
		srt_packets = extract_srt_packets(csv_filepath)
	except UnexpectedColumnsNumber as error:
		print(
			f'Exception captured: {error} '
			'Please try running the script with --overwrite option.'
		)
		return

	if type == PacketTypes.srt.value:
		packets = srt_packets
	if type == PacketTypes.data.value:
		packets = extract_data_packets(srt_packets)
	if type == PacketTypes.probing.value:
		packets = extract_probing_packets(srt_packets)
	if type == PacketTypes.umsg_ack.value:
		packets = extract_umsg_ack_packets(srt_packets)

	# Print the first 20 rows of the dataframe with extracted packets
	print('The result dataframe is the following:')
	print(packets.head(20))

	# Save extracted packets to .csv
	if save:
		print('Writing to .csv file ...')
		name, _ = csv_filepath.name.split('.')
		packets.to_csv(csv_filepath.parent / f'{name}-{type}.csv', sep=';')


if __name__ == '__main__':
	main()