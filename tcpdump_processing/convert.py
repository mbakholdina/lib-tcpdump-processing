""" Module designed to convert .pcapng or .pcap tcpdump trace file into .csv one. """

import pathlib
import subprocess


class IsNotPcapFile(Exception):
	pass


class PcapProcessingFailed(Exception):
	pass


class FileDoesNotExist(Exception):
	pass


class DirectoryDoesNotExist(Exception):
	pass


def convert_to_csv(
	filepath: pathlib.Path,
	overwrite: bool=False
) -> pathlib.Path:
	""" 
	Convert .pcapng or .pcap tcpdump trace file into .csv one. During conversion,
	only SRT packets are extracted.

	Attributes:
		filepath: 
			:class:`pathlib.Path` path to tcpdump trace file.
		overwrite:
			True/False if already existing .csv file should be / should
			not be overwritten.

	Returns:
		:class:`pathlib.Path` path to a result csv file.

	Raises:
		:exc:`FileDoesNotExist` 
			if `filepath` file does not exist,
		:exc:`IsNotPcapFile` 
			if `filepath` does not correspond to .pcapng or .pcap file,
		:exc:`PcapProcessingFailed` 
			if tcpdump trace file .csv file processing was not successful.
	"""
	if not filepath.exists():
		raise FileDoesNotExist(filepath)

	filename = filepath.name
	if not filename.endswith('.pcapng'):
		if not filename.endswith('.pcap'):
			raise IsNotPcapFile(
				f'{filepath} does not correspond to .pcapng or .pcap file'
			)
	name, _ = filename.split('.')
	csv_filename = name + '.csv'
	csv_filepath = filepath.parent / csv_filename

	if csv_filepath.exists() and not overwrite:
		print(
			'Skipping .pcapng (or .pcap) tcpdump trace file processing to '
			f'.csv, .csv file already exists: {csv_filepath}.'
		)
		return csv_filepath	

	print(f'Processing .pcapng (or .pcap) tcpdump trace file to .csv: {filepath}')
	args = [
		'tshark',
		'-r', str(filepath),
		'--disable-protocol', 'udt',	# Disable UDT protocol, otherwise SRT packets will be treated as UDT ones
		'-Y', 'srt',					# Extract SRT packets only
		'-T', 'fields', 
		'-e', '_ws.col.No.',
		'-e', 'frame.time',
		'-e', '_ws.col.Time',
		'-e', '_ws.col.Source',
		'-e', '_ws.col.Destination',
		'-e', '_ws.col.Protocol',
		'-e', '_ws.col.Length',
		'-e', '_ws.col.Info',
		'-e', 'udp.length',
		'-e', 'srt.iscontrol',
		'-e', 'srt.type',
		'-e', 'srt.seqno',
		'-e', 'srt.msg.rexmit',
		'-e', 'srt.timestamp',
		'-e', 'srt.id',
		'-e', 'srt.ack_seqno',
		'-e', 'srt.rtt',
		'-e', 'srt.rttvar',
		'-e', 'srt.rate',
		'-e', 'srt.bw',
		'-e', 'srt.rcvrate',
		'-e', 'data.len',
		'-E', 'header=y',
		'-E', 'separator=;',
	]
	with csv_filepath.open(mode='w') as f:
		process = subprocess.run(args, stdout=f)	
		if process.returncode != 0:
			raise PcapProcessingFailed(
				'Processing .pcapng (or .pcap) tcpdump trace file to .csv '
				f'has failed with the code: {process.returncode}'
			)
	print(f'Processing finished: {csv_filepath}')
	
	return csv_filepath