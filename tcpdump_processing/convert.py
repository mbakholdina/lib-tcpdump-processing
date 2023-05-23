""" Module designed to convert .pcap(ng) tcpdump trace file into .csv one. """

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
	overwrite: bool=False,
	decode_as_srt: bool=False,
	port: str=None
) -> pathlib.Path:
	""" 
	Convert .pcap(ng) tcpdump trace file into .csv one. During conversion,
	by default UDP packets are extracted. If `decode_as_srt` equals True,
	packets are decoded as SRT on a particular port.

	Attributes:
		filepath: 
			:class:`pathlib.Path` path to tcpdump trace file.
		overwrite:
			True if already existing .csv file should be overwritten.
		decode_as_srt:
			True if packets should be decoded as SRT packets
			on a particular port.
		port:
			Port on which packets should be decoded as SRT if `decode_as_srt`
			equals True.

	Returns:
		:class:`pathlib.Path` path to a result csv file.

	Raises:
		:exc:`FileDoesNotExist` 
			if `filepath` file does not exist,
		:exc:`IsNotPcapFile` 
			if `filepath` does not correspond to .pcap(ng) file,
		:exc:`PcapProcessingFailed` 
			if tcpdump trace file .csv file processing was not successful.
	"""
	if not filepath.exists():
		raise FileDoesNotExist(filepath)

	suffix = filepath.suffix
	if not suffix.endswith('.pcapng'):
		if not suffix.endswith('.pcap'):
			raise IsNotPcapFile(
				f'{filepath} does not correspond to .pcap(ng) file'
			)

	csv_filepath = filepath.parent / (filepath.stem + '.csv')
	if csv_filepath.exists() and not overwrite:
		print(
			'Skipping .pcap(ng) tcpdump trace file processing to '
			f'.csv, .csv file already exists: {csv_filepath}.'
		)
		return csv_filepath	

	print(f'Processing .pcap(ng) tcpdump trace file to .csv: {filepath}')
	args = [
		'tshark',
		'-r', str(filepath),
		'--disable-protocol', 'udt',				# Disable UDT protocol, otherwise SRT packets will be treated as UDT ones
	]

	if decode_as_srt:
		args += ['-d', f'udp.port=={port},srt']		# Decode UDP packets as SRT on a particular port
	else:
		args += ['-Y', 'udp',]						# Decode packets as UDP

	args += [
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
		'-e', 'udp.srcport',
		'-e', 'udp.dstport',
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
				'Processing .pcap(ng) tcpdump trace file to .csv '
				f'has failed with the code: {process.returncode}'
			)
	print(f'Processing finished: {csv_filepath}')
	
	return csv_filepath