"""
Module designed to extract packets of interest out of the .pcap(ng)
tcpdump trace file. Currently only trace files with one data flow
are supported.
"""

import enum
import pathlib

import click
import dateutil
import pandas as pd

import tcpdump_processing.convert as convert


class AutoName(enum.Enum):
	def _generate_next_value_(name, start, count, last_values):
		return name


@enum.unique
class PacketTypes(AutoName):
	srt = enum.auto()
	data = enum.auto()
	control = enum.auto()
	probing = enum.auto()
	umsg_handshake = enum.auto()
	umsg_ack = enum.auto()


PACKET_TYPES = [name for name, member in PacketTypes.__members__.items()]


class UnexpectedColumnsNumber(Exception):
	pass

class EmptyCSV(Exception):
	pass

class NoUDPPacketsFound(Exception):
	pass

class NoSRTPacketsFound(Exception):
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
			if .csv file contains unexpected number of columns.
		:exc: `EmptyCSV`
			if neither SRT, nor UDP packets are present in .csv file.
		:exc: `NoUDPPacketsFound`
			if there is no SRT handshake and there are no UDP packets found in .csv file.
		:exc: `NoSRTPacketsFound`
			if there is no SRT handshake, but there are UDP packets found in .csv file.
			Those UDP packets could be further parsed as SRT ones.
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
		'udp.srcport',
		'udp.dstport',
		'srt.iscontrol',
		'srt.type',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'srt.ack_seqno',
		'srt.rtt',
		'srt.rttvar',
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
		'float32',		# udp.length
		'object',		# ws.srcport
		'object',		# ws.dstport
		'float32',		# srt.iscontrol
		'category',		# srt.type
		'float64',		# srt.seqno
		'float32',		# srt.msg.rexmit
		'float64',		# srt.timestamp
		'category',		# srt.id
		'float64',		# srt.ack_seqno
		'float64',		# srt.rtt
		'float64',		# srt.rttvar
		'float64',		# srt.rate
		'float64',		# srt.bw
		'float64',		# srt.rcvrate
		'float32'		# data.len
	]

	columns_types = dict(zip(columns, types))
	packets = pd.read_csv(filepath, sep=';', dtype=columns_types)

	if len(packets.columns) != len(columns):
		raise UnexpectedColumnsNumber(
			f'Unexpected columns number in .csv file: {filepath}. '
			'Try running the script with --overwrite option.'
		)

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
		'udp.srcport',
		'udp.dstport',
		'srt.iscontrol',
		'srt.type',
		'srt.seqno',
		'srt.msg.rexmit',
		'srt.timestamp',
		'srt.id',
		'srt.ack_seqno',
		'srt.rtt',
		'srt.rttvar',
		'srt.rate',
		'srt.bw',
		'srt.rcvrate',
		'data.len'
	]

	# Packets dataframe may consist of both SRT and UDP packets, maybe empty as well
	if packets.empty:
		raise EmptyCSV(
			'Neither SRT, nor UDP packets are present in .csv file. '
			'Sounds like original .pcap(ng) file is empty or consists of non-UDP packets.'
		)

	srt_packets = packets[packets['ws.protocol'] == 'SRT'].copy()

	if srt_packets.empty:
		# With a high probability there is no SRT handshake present in the original .pcap(ng) file
		print(
			'No SRT packets found in .csv file. '
			'Sounds like there is no SRT handshake in the original .pcap(ng) file. '
			'Extracting UDP packets.'
		)

		udp_packets = packets[packets['ws.protocol'] == 'UDP'].copy()

		if udp_packets.empty:
			raise NoUDPPacketsFound(
				'No UDP packets found in .csv file. '
				'Sounds like there is no UDP packets present in the original .pcap(ng) file.'
			)

		ports = udp_packets.groupby(['udp.srcport', 'udp.dstport'])['ws.no'].count()

		raise NoSRTPacketsFound(
			f'There are UDP packets in .csv file on ports: \n{ports}\n'
			'Try to decode UDP packets as SRT ones by running the script with --overwrite and --port options.'
		)

	# SRT packets found in .csv file.
	# TODO: Using ports 'udp.srcport', 'udp.dstport', check that there is only one stream inside
	
	# NOTE: When adding a combination "offset abbreviation <-> timezone", it's recommended
	# to add both standard and daylight savings time offsets for each timezone
	# (like CET and CEST for 'Europe/Berlin')
	# https://stackoverflow.com/questions/67061724/panda-to-datetime-raises-warning-tzname-cet-identified-but-not-understood
	tzmapping = {
		'CET':	dateutil.tz.gettz('Europe/Berlin'),
		'CEST':	dateutil.tz.gettz('Europe/Berlin')
	}

	# NOTE: This is done to convert Windows time offsets into appropriate pandas format
	# https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-time-zones?view=windows-11
	srt_packets['frame.time'] = srt_packets['frame.time'].str.replace('W. Europe Standard Time', 'CET')
	srt_packets['frame.time'] = srt_packets['frame.time'].str.replace('W. Europe Daylight Time', 'CEST')

	srt_packets['frame.time'] = srt_packets['frame.time'].apply(dateutil.parser.parse, tzinfos=tzmapping)
	srt_packets['frame.time'] = srt_packets['frame.time'].dt.tz_convert('UTC')

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


def extract_control_packets(srt_packets: pd.DataFrame) -> pd.DataFrame:
	"""
	Extract SRT CONTROL packets from SRT packets (both DATA and CONTROL)
	`srt_packets` dataframe. 
	
	Attributes:
		srt_packets: 
			:class:`pd.DataFrame` dataframe with SRT packets (both DATA and 
			CONTROL) obtained from the .csv tcpdump trace file using
			`extract_srt_packets` function.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT CONTROL packets or
		an empty dataframe if there is no CONTROL packets found.
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
		'srt.rtt',
		'srt.rttvar',
		'srt.rate',
		'srt.bw',
		'srt.rcvrate',
	]
	control = srt_packets.loc[srt_packets['srt.iscontrol'] == 1, columns]

	return control


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


def extract_umsg_handshake_packets(srt_packets: pd.DataFrame) -> pd.DataFrame:
	"""
	Extract SRT UMSG_HANDSHAKE CONTROL packets from SRT packets
	(both DATA and CONTROL) `srt_packets` dataframe. 
	
	Attributes:
		srt_packets: 
			:class:`pd.DataFrame` dataframe with SRT packets (both DATA and 
			CONTROL) obtained from the .csv tcpdump trace file using
			`extract_srt_packets` function.

	Returns:
		:class:`pd.DataFrame` dataframe with SRT UMSG_HANDSHAKE CONTROL
		packets or an empty dataframe if there is no UMSG_HANDSHAKE
		packets found.
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
	]
	control = extract_control_packets(srt_packets)
	umsg_handshake = control.loc[control['srt.type'] == '0x00000000', columns]

	return umsg_handshake


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
	control = extract_control_packets(srt_packets)

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
	umsg_ack['srt.rtt'] = umsg_ack['srt.rtt'].astype('int64')
	umsg_ack['srt.rttvar'] = umsg_ack['srt.rttvar'].astype('int64')
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
	help=	'Packet type to extract: '
			'SRT (both DATA and CONTROL), SRT DATA, SRT CONTROL, '
			'SRT DATA probing, SRT CONTROL UMSG_HANDSHAKE, '
			'or SRT CONTROL UMSG_ACK packets.',
	show_default=True
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcap(ng) '
			'one at the previous iterations of running the script.',
	show_default=True
)
@click.option(
	'--save/--no-save',
	default=False,
	help='Save dataframe with extracted packets into .csv file.',
	show_default=True
)
@click.option(
	'--port',
	help=	'Decode packets as SRT on a specified port. '
			'This option is helpful when there is no SRT handshake in .pcap(ng) file. '
			'Should be used together with --overwrite option.'
)
def main(path, type, overwrite, save, port):
	"""
	This script parses .pcap(ng) tcpdump trace file,
	saves the output in .csv format nearby the original file, extract packets 
	of interest and saves the obtained dataframe in .csv format nearby the 
	original file.
	"""
	# Convert .pcap(ng) to .csv tcpdump trace file
	pcap_filepath = pathlib.Path(path)
	if port is not None:
		csv_filepath = convert.convert_to_csv(pcap_filepath, overwrite, True, port)
	else:
		csv_filepath = convert.convert_to_csv(pcap_filepath, overwrite)

	# Extract packets of interest
	try:
		srt_packets = extract_srt_packets(csv_filepath)
	except (UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound) as error:
		print(f'{error}')
		return

	if type == PacketTypes.srt.value:
		packets = srt_packets
	if type == PacketTypes.data.value:
		packets = extract_data_packets(srt_packets)
	if type == PacketTypes.control.value:
		packets = extract_control_packets(srt_packets)
	if type == PacketTypes.probing.value:
		packets = extract_probing_packets(srt_packets)
	if type == PacketTypes.umsg_handshake.value:
		packets = extract_umsg_handshake_packets(srt_packets)
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
