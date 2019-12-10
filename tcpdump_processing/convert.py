""" Module designed to convert .pcapng tcpdump trace file into .csv one. """

import pathlib
import subprocess


class IsNotPcapngFile(Exception):
	pass


class PcapngProcessingFailed(Exception):
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
	Convert .pcapng tcpdump trace file into .csv one.

	Attributes:
		filepath: 
			:class:`pathlib.Path` path to .pcapng file.
		overwrite:
			True/False if already existing .csv file should be / should
			not be overwritten.

	Returns:
		:class:`pathlib.Path` path to a result csv file.

	Raises:
		:exc:`FileDoesNotExist` 
			if `filepath` file does not exist,
		:exc:`IsNotPcapngFile` 
			if `filepath` does not correspond to .pcapng file,
		:exc:`PcapngProcessingFailed` 
			if .pcapng to .csv file processing was not successful.
	"""
	if not filepath.exists():
		raise FileDoesNotExist(filepath)

	filename = filepath.name
	if not filename.endswith('.pcapng'):
		raise IsNotPcapngFile(
			f'{filepath} does not correspond to .pcapng file'
		)
	name, _ = filename.split('.')
	csv_filename = name + '.csv'
	csv_filepath = filepath.parent / csv_filename

	if csv_filepath.exists() and not overwrite:
		print(
			f'Skipping .pcapng to .csv tcpdump trace file processing, '
			f'.csv file already exists: {filepath}.'
		)
		return csv_filepath	

	print(f'Processing .pcapng to .csv tcpdump trace file: {filepath}')
	args = [
		'tshark',
		'-r', str(filepath),
		'-T', 'fields', 
		'-e', '_ws.col.No.',
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
			raise PcapngProcessingFailed(
				f'.pcapng to .csv tcpdump trace file processing failed ',
				f'with the code: {process.returncode}'
			)
	print(f'Processing finished: {csv_filepath}')
	
	return csv_filepath