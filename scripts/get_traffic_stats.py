"""
Script designed to process .pcap(ng) files and generate a report
with network traffic statistics.
"""
import pathlib

import click
import pandas as pd

from tcpdump_processing.convert import convert_to_csv
from tcpdump_processing.extract_packets import extract_srt_packets, UnexpectedColumnsNumber, EmptyCSV, NoUDPPacketsFound, NoSRTPacketsFound


def to_percent(value, base):
	return round(value / base * 100, 4)


def to_str(first, second):
	return str(first) + '(' + str(second) + ')'


def to_rate(value, duration):
	return round(value * 8 / duration / 1000000, 2)


class TrafficStatsIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts        = (srt_packets['srt.iscontrol'] == 1)
		self.ctrl_pkts_ack    = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000002')
		self.ctrl_pkts_ackack = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000006')
		self.ctrl_pkts_nak    = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000003')

		self.data_pkts     = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = (self.data_pkts) & (srt_packets['srt.msg.rexmit'] == 0)
		self.data_pkts_rex = (self.data_pkts) & (srt_packets['srt.msg.rexmit'] == 1)


class TrafficStats:
	def __init__(self, srt_packets):
		self.srt_packets = srt_packets
		self.index = TrafficStatsIndex(srt_packets)


	def bytes_to_Mbps(self, bytes):
		return bytes * 8 / self.duration / 1000000


	@property
	def data_pkts(self):
		return self.srt_packets[self.index.data_pkts]


	@property
	def data_pkts_org(self):
		return self.srt_packets[self.index.data_pkts_org]


	@property
	def data_pkts_rex(self):
		return self.srt_packets[self.index.data_pkts_rex]


	@property
	def ctrl_pkts(self):
		return self.srt_packets[self.index.ctrl_pkts]


	@property
	def duration(self):
		# Calculate duration in seconds.
		start    = self.data_pkts.iloc[0]['ws.time']
		stop      = self.data_pkts.iloc[-1]['ws.time']
		return (stop - start)


	def count_packets(self):
		# Count the number of packets.
		pkts          = len(self.srt_packets.index)
		data_pkts     = self.index.data_pkts.sum()
		data_pkts_org = self.index.data_pkts_org.sum()
		data_pkts_rex = self.index.data_pkts_rex.sum()

		ctrl_pkts        = self.index.ctrl_pkts.sum()
		ctrl_pkts_ack    = self.index.ctrl_pkts_ack.sum()
		ctrl_pkts_ackack = self.index.ctrl_pkts_ackack.sum()
		ctrl_pkts_nak    = self.index.ctrl_pkts_nak.sum()

		return {
			'pkts': pkts,
			'data_pkts': data_pkts,
			'data_pkts_org': data_pkts_org,
			'data_pkts_rex': data_pkts_rex,
			'ctrl_pkts': ctrl_pkts,
			'ctrl_pkts_ack': ctrl_pkts_ack,
			'ctrl_pkts_ackack': ctrl_pkts_ackack,
			'ctrl_pkts_nak': ctrl_pkts_nak,
		}

	
	def count_retransmissions(self):
		# Calculate how much packets were retransmitted once, twice, 3x times, etc.
		rexmit_pkts              = self.data_pkts_rex.copy()
		rexmit_pkts['srt.seqno'] = rexmit_pkts['srt.seqno'].astype('int32')
		rexmit_pkts['seqno']     = rexmit_pkts['srt.seqno']
		rexmits                  = rexmit_pkts.groupby(['srt.seqno'])['seqno'].count()

		once    = rexmits[rexmits == 1].count()
		twice   = rexmits[rexmits == 2].count()
		x3      = rexmits[rexmits == 3].count()
		x4      = rexmits[rexmits == 4].count()
		x5_more = rexmits[rexmits > 4].count()

		return {
			'once': once,
			'twice': twice,
			'x3': x3,
			'x4': x4,
			'x5_more': x5_more,
			'once_total': once,
			'twice_total': twice * 2,
			'x3_total': x3 * 3,
			'x4_total': x4 * 4,
			'x5_more_total': len(rexmit_pkts) - once - twice * 2 - x3 * 3 - x4 * 4,
		}


	def print_traffic(self):
		print(" Traffic ".center(70, "~"))

		print(f"- SRT DATA pkts")
		print(f"  - SRT payload + SRT hdr + UDP hdr (orig+retrans)  {to_rate(self.data_pkts['udp.length'].sum(), self.duration):>13} Mbps")
		print(f"  - SRT payload + SRT hdr (orig+retrans)            {to_rate(self.data_pkts['data.len'].sum() + 16 * len(self.data_pkts), self.duration):>13} Mbps")
		print(f"  - SRT payload (orig+retrans)                      {to_rate(self.data_pkts['data.len'].sum(), self.duration):>13} Mbps")
		print(f"  - SRT payload + SRT hdr + UDP hdr (orig)          {to_rate(self.data_pkts_org['udp.length'].sum(), self.duration):>13} Mbps")
		print(f"  - SRT payload + SRT hdr (orig)                    {to_rate(self.data_pkts_org['data.len'].sum() + 16 * len(self.data_pkts_org), self.duration):>13} Mbps")
		print(f"  - SRT payload (orig)                              {to_rate(self.data_pkts_org['data.len'].sum(), self.duration):>13} Mbps")


	def print_notations(self):
		print(" Notations ".center(70, "~"))
		print("pkts - packets")
		print("hdr - header")
		print("orig - original")
		print("retrans - retransmitted")
		print("".center(70, "~"))


	def generate_snd_report(self):
		cnt = self.count_packets()
		rexmits_cnt = self.count_retransmissions()

		# Calculate the number of missing in the dump original data packets
		# that were either dropped by the SRT sender, or UDP socket.
		# Reordered packets are not taken into account, so if a packet is reordered and
		# comes later, it will not be included into statistic.
		seqnos_org = self.data_pkts_org['srt.seqno'].astype('int32')
		# Removing duplicates in sent original packets.
		seqnos_org = seqnos_org.drop_duplicates()
		data_pkts_org_missing_cnt = int((seqnos_org.diff().dropna() - 1).sum())

		print(" SRT Packets ".center(70, "~"))

		print(f"- SRT DATA+CONTROL pkts  {cnt['pkts']:>35}")

		print(f"- SRT DATA pkts          {cnt['data_pkts']:>35}")

		print(
			f"  - Original DATA pkts sent       {cnt['data_pkts_org']:>26}"
			f" {to_percent(cnt['data_pkts_org'], cnt['data_pkts']):>8}%"
			"  out of orig+retrans sent DATA pkts"
		)

		print(
			f"  - Retransmitted DATA pkts sent  {cnt['data_pkts_rex']:>26}"
			f" {to_percent(cnt['data_pkts_rex'], cnt['data_pkts']):>8}%"
			"  out of orig+retrans sent DATA pkts"
		)
		print(f"      Once   {to_str(rexmits_cnt['once'], rexmits_cnt['once']):>47} {to_percent(rexmits_cnt['once'], cnt['data_pkts']):>8}%")
		print(f"      Twice  {to_str(rexmits_cnt['twice'], rexmits_cnt['twice_total']):>47} {to_percent(rexmits_cnt['twice_total'], cnt['data_pkts']):>8}%")
		print(f"      3×     {to_str(rexmits_cnt['x3'], rexmits_cnt['x3_total']):>47} {to_percent(rexmits_cnt['x3_total'], cnt['data_pkts']):>8}%")
		print(f"      4×     {to_str(rexmits_cnt['x4'], rexmits_cnt['x4_total']):>47} {to_percent(rexmits_cnt['x4_total'], cnt['data_pkts']):>8}%")
		print(f"      5+     {to_str(rexmits_cnt['x5_more'], rexmits_cnt['x5_more_total']):>47} {to_percent(rexmits_cnt['x5_more_total'], cnt['data_pkts']):>8}%")

		print(
			f"- Original DATA pkts missing       {data_pkts_org_missing_cnt:>25}"
			f" {to_percent(data_pkts_org_missing_cnt, (cnt['data_pkts_org']+data_pkts_org_missing_cnt)):>8}%"
			"  out of orig sent+missing DATA pkts"
		)

		print(f"- SRT CONTROL pkts     {cnt['ctrl_pkts']:>37}")
		print(f"  - ACK pkts received  {cnt['ctrl_pkts_ack']:>37}")
		print(f"  - ACKACK pkts sent   {cnt['ctrl_pkts_ackack']:>37}")
		print(f"  - NAK pkts received  {cnt['ctrl_pkts_nak']:>37}")

		self.print_traffic()

		print(" Overhead ".center(70, "~"))

		print(f"- SRT DATA pkts")
		print(
			"  - UDP+SRT headers over SRT payload (orig)"
			f"{round(to_rate(self.data_pkts_org['udp.length'].sum(), self.duration) * 100 / to_rate(self.data_pkts_org['data.len'].sum(), self.duration) - 100, 2):>25} %"
		)
		print(
			"  - Retransmitted over original sent pkts"
			f"{to_percent(cnt['data_pkts_rex'], cnt['data_pkts_org']):>27} %"
		)

		self.print_notations()


	def generate_rcv_report(self):
		cnt = self.count_packets()
		rexmits_cnt = self.count_retransmissions()

		# Calculate the number of lost original data packets as the number
		# of original data packets that haven't reached the receiver.
		# Reordered packets are not taken into account, so if a packet is reordered and
		# comes later, it will not be included into statistic.
		seqnos_org = self.data_pkts_org['srt.seqno'].astype('int32')
		# Removing duplicates in received original packets.
		seqnos_org = seqnos_org.drop_duplicates()
		data_pkts_org_lost_cnt = int((seqnos_org.diff().dropna() - 1).sum())
		
		# The number of packets considered unrecovered at the receiver.
		# It means neither original, nor re-transmitted packet with
		# a particular sequence number has reached the destination.
		seqnos = self.data_pkts['srt.seqno'].astype('int32').copy()
		seqnos = seqnos.drop_duplicates().sort_values()
		data_pkts_unrecovered_cnt = int((seqnos.diff().dropna() - 1).sum())
		
		# The number of recovered at the receiver side packets.
		data_pkts_recovered_cnt = data_pkts_org_lost_cnt - data_pkts_unrecovered_cnt

		# The number of original DATA packets (received + lost).
		data_pkts_org_rcvd_lost_cnt = cnt['data_pkts_org'] + data_pkts_org_lost_cnt

		print(" SRT Packets ".center(70, "~"))

		print(f"- SRT DATA+CONTROL pkts  {cnt['pkts']:>35}")

		print(f"- SRT DATA pkts          {cnt['data_pkts']:>35}")

		print(
			f"  - Original DATA pkts received       {cnt['data_pkts_org']:>22}"
			f" {to_percent(cnt['data_pkts_org'], cnt['data_pkts']):>8}%"
			"  out of orig+retrans received DATA pkts"
		)

		print(
			f"  - Retransmitted DATA pkts received  {cnt['data_pkts_rex']:>22}"
			f" {to_percent(cnt['data_pkts_rex'], cnt['data_pkts']):>8}%"
			"  out of orig+retrans received DATA pkts"
		)
		print(f"      Once   {to_str(rexmits_cnt['once'], rexmits_cnt['once']):>47} {to_percent(rexmits_cnt['once'], cnt['data_pkts']):>8}%")
		print(f"      Twice  {to_str(rexmits_cnt['twice'], rexmits_cnt['twice_total']):>47} {to_percent(rexmits_cnt['twice_total'], cnt['data_pkts']):>8}%")
		print(f"      3×     {to_str(rexmits_cnt['x3'], rexmits_cnt['x3_total']):>47} {to_percent(rexmits_cnt['x3_total'], cnt['data_pkts']):>8}%")
		print(f"      4×     {to_str(rexmits_cnt['x4'], rexmits_cnt['x4_total']):>47} {to_percent(rexmits_cnt['x4_total'], cnt['data_pkts']):>8}%")
		print(f"      5+     {to_str(rexmits_cnt['x5_more'], rexmits_cnt['x5_more_total']):>47} {to_percent(rexmits_cnt['x5_more_total'], cnt['data_pkts']):>8}%")

		# The percentage of original DATA packets lost is calculated out of
		# original DATA packets (received + lost) which equals sent unique
		# packets approximately.
		print(
			f"- Original DATA pkts lost       {data_pkts_org_lost_cnt:>28}"
			f" {to_percent(data_pkts_org_lost_cnt, data_pkts_org_rcvd_lost_cnt):>8}%"
			"  out of orig received+lost DATA pkts"
		)
		print(
			f"  - Recovered pkts  {data_pkts_recovered_cnt:>40}"
			f" {to_percent(data_pkts_recovered_cnt, data_pkts_org_rcvd_lost_cnt):>8}%"
		)
		print(
			f"  - Unrecovered pkts  {data_pkts_unrecovered_cnt:>38}"
			f" {to_percent(data_pkts_unrecovered_cnt, data_pkts_org_rcvd_lost_cnt):>8}%"
		)

		print(f"- SRT CONTROL pkts                {cnt['ctrl_pkts']:>26}")
		print(f"  - ACK pkts sent                 {cnt['ctrl_pkts_ack']:>26}")
		print(f"  - ACKACK pkts received          {cnt['ctrl_pkts_ackack']:>26}")
		print(f"  - NAK pkts sent                 {cnt['ctrl_pkts_nak']:>26}")

		self.print_traffic()
		
		print(" Overhead ".center(70, "~"))

		print(f"- SRT DATA pkts")
		print(
			"  - UDP+SRT headers over SRT payload (orig)"
			f"{round(to_rate(self.data_pkts_org['udp.length'].sum(), self.duration) * 100 / to_rate(self.data_pkts_org['data.len'].sum(), self.duration) - 100, 2):>25} %"
		)
		print(
			"  - Retransmitted over original (received+lost) pkts"
			f"{to_percent(cnt['data_pkts_rex'], data_pkts_org_rcvd_lost_cnt):>16} %"
		)

		self.print_notations()


	def show_unrecovered_packets(self, parent, stem):
		# Show and save to file sequence numbers of unrecovered at the
		# receiver side packets.

		# The number of packets considered unrecovered at the receiver.
		# It means neither original, nor re-transmitted packet with
		# a particular sequence number has reached the destination.
		seqnos = self.data_pkts['srt.seqno'].astype('int32').copy()
		seqnos = seqnos.drop_duplicates().sort_values()

		# Get sequence numbers of unrecovered packets.
		df = pd.DataFrame(seqnos)
		df['diff'] = df['srt.seqno'].diff()
		df.dropna(inplace=True)
		df['diff'] = df['diff'].astype('int32') - 1
		df = df[df['diff'] != 0]
		df['start'] = df['srt.seqno'] - df['diff']

		list_unrec = df[['diff', 'start']].values.tolist()

		unrec_pkts_seqnos = []
		for sublist in list_unrec:
			diff, start = sublist
			for i in range(0, diff):
				unrec_pkts_seqnos.append(start + i)

		unrec_pkts_seqnos = pd.Series(unrec_pkts_seqnos)
		path_unrec = parent / (stem + '-unrec-pkts-seqnos.csv')
		unrec_pkts_seqnos.to_csv(path_unrec)
		print(f'\nUnrecovered at the receiver side packets have the following sequence numbers. They are stored in {path_unrec} file.')
		print(unrec_pkts_seqnos)


@click.command()
@click.argument(
	'path', 
	type=click.Path(exists=True)
)
@click.option(
	'--side',
	type=click.Choice(['snd', 'rcv'], case_sensitive=False),
	required=True,
	help='The side .pcap(ng) file was collected at.'
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcap(ng) '
			'one at the previous iterations of running the script.',
	show_default=True
)
@click.option(
	'--show-unrec-pkts/--no-show-unrec-pkts',
	default=False,
	help=	'Show sequence numbers of unrecovered at the receiver side '
			'packets. Save the list of sequence numbers into respective .csv file.',
	show_default=True
)
@click.option(
	'--port',
	help=	'Decode packets as SRT on a specified port. '
			'This option is helpful when there is no SRT handshake in .pcap(ng) file. '
			'Should be used together with --overwrite option.'
)
def main(path, side, overwrite, show_unrec_pkts, port):
	"""
	Script designed to process .pcap(ng) files and generate a report
	with network traffic statistics.
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

	stats = TrafficStats(srt_packets)

	if (side == 'snd'):
		stats.generate_snd_report()
		return
	
	if (side == 'rcv'):
		stats.generate_rcv_report()
		if (show_unrec_pkts):
			stats.show_unrecovered_packets(pathlib.Path(path).parent, pathlib.Path(path).stem)


if __name__ == '__main__':
	main()
