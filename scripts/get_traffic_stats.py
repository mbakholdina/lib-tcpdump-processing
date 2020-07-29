"""
Script designed to collect and output network traffic statistics.
"""
import pathlib

import click
import pandas as pd

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


class SRTTrafficStatsIndex:
	def __init__(self, srt_packets):
		self.ctrl_pkts        = (srt_packets['srt.iscontrol'] == 1)
		self.ctrl_pkts_ack    = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000002')
		self.ctrl_pkts_ackack = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000006')
		self.ctrl_pkts_nak    = (self.ctrl_pkts) & (srt_packets['srt.type'] == '0x00000003')

		self.data_pkts = (srt_packets['srt.iscontrol'] == 0)
		self.data_pkts_org = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 0)
		self.data_pkts_rex = self.data_pkts & (srt_packets['srt.msg.rexmit'] == 1)



class TrafficStats:
	def __init__(self, srt_packets):
		self.srt_packets = srt_packets
		self.index = SRTTrafficStatsIndex(srt_packets)
		self.time_start = srt_packets.iloc[ 0]['ws.time']
		self.time_stop  = srt_packets.iloc[-1]['ws.time']
		self.duration_sec  = self.time_start - self.time_stop
		return

	def bytes_to_Mbps(self, bytes):
		return bytes * 8 / self.duration_sec / 1000000

	@property
	def srt_pkts_data(self):
		return self.srt_packets[self.index.data_pkts]

	@property
	def srt_pkts_data_org(self):
		return self.srt_packets[self.index.data_pkts_org]

	@property
	def srt_pkts_data_rex(self):
		return self.srt_packets[self.index.data_pkts_rex]

	@property
	def srt_pkts_ctrl(self):
		return self.srt_packets[self.index.ctrl_pkts]

	def generate_report(self):
		srt_pkts_cnt           = len(self.srt_packets.index)
		srt_data_pkts_cnt      = self.index.data_pkts.sum()	    # count true values
		srt_data_pkts_org_cnt  = self.index.data_pkts_org.sum() # count true values
		srt_data_pkts_rex_cnt  = self.index.data_pkts_rex.sum() # count true values

		srt_ctrl_pkts_cnt = self.index.ctrl_pkts.sum()
		srt_ctrl_pkts_ack_cnt = self.index.ctrl_pkts_ack.sum()
		srt_ctrl_pkts_ackack_cnt = self.index.ctrl_pkts_ackack.sum()
		srt_ctrl_pkts_nak_cnt = self.index.ctrl_pkts_nak.sum()

		# Calculating lost packets as the number of original packets that
		# haven't reached the receiver. Reordering is taken into account,
		# so if a packet is reordered and comes later, it will not be
		# considered as lost
		seqnos_org = self.srt_pkts_data_org['srt.seqno'].astype('int32')
		# Removing duplicates in received original packets
		seqnos_org = seqnos_org.drop_duplicates()
		srt_pkts_data_org_lost = int((seqnos_org.diff() - 1).sum())

		# Calculating dropped packets as the number of packets considered
		# missing at the receiver. It means nor original, neither
		# retransmitted packet with a particular sequence number hasn't
		# reached the destination. Latency is not taken into account,
		# because it's tricky to do. It's a limitation of the current approach.
		seqnos = self.srt_pkts_data['srt.seqno'].astype('int32').copy()
		seqnos = seqnos.drop_duplicates().sort_values()
		srt_data_pkts_droppped = int((seqnos.diff() - 1).sum())

		rexmit_pkts                   = self.srt_pkts_data_rex.copy()
		rexmit_pkts['srt.seqno']      = rexmit_pkts['srt.seqno'].astype('int32')
		rexmit_pkts['seqno']          = rexmit_pkts['srt.seqno']
		srt_data_rexmits              = rexmit_pkts.groupby(['srt.seqno'])['seqno'].count()
		srt_data_rex_once_cnt         = srt_data_rexmits[srt_data_rexmits == 1].count()
		srt_data_rex_twice_cnt        = srt_data_rexmits[srt_data_rexmits == 2].count()
		srt_data_rex_3x_cnt           = srt_data_rexmits[srt_data_rexmits == 3].count()
		srt_data_rex_4x_cnt           = srt_data_rexmits[srt_data_rexmits == 4].count()
		srt_data_rex_5x_more_cnt      = srt_data_rexmits[srt_data_rexmits > 4].count()

		def to_percent(value, base):
			return round(value / base * 100, 2)

		data_pkts_org_received_lost = srt_data_pkts_org_cnt + srt_pkts_data_org_lost

		print(" SRT Packets ".center(70, "~"))
		
		print(f"- SRT DATA pkts                   {srt_data_pkts_cnt:>26}")
		print(
			f"  - Original DATA pkts received   {srt_data_pkts_org_cnt:>26}"
			f" {to_percent(srt_data_pkts_org_cnt, srt_data_pkts_cnt):>8}%"
			"  out of SRT DATA pkts"
		)
		print(
			f"  - Original DATA pkts lost       {srt_pkts_data_org_lost:>26}"
			f" {to_percent(srt_pkts_data_org_lost, data_pkts_org_received_lost):>8}%"
			"  out of original DATA pkts (received+lost)"
		)
		print(
			f"  - DATA pkts retransmitted       {srt_data_pkts_rex_cnt:>26}"
			f" {to_percent(srt_data_pkts_rex_cnt, srt_data_pkts_cnt):>8}%"
			"  out of SRT DATA pkts"
		)
		print(
			f"  - DATA pkts dropped             {srt_data_pkts_droppped:>26}"
			f" {to_percent(srt_data_pkts_droppped, data_pkts_org_received_lost):>8}%"
			"  out of original DATA pkts (received+lost)"
		)
	
		print(f"- SRT CONTROL pkts                {srt_ctrl_pkts_cnt:>26}")
		print(f"  - ACK pkts sent                 {srt_ctrl_pkts_ack_cnt:>26}")
		print(f"  - ACKACK pkts received          {srt_ctrl_pkts_ackack_cnt:>26}")
		print(f"  - NAK pkts sent                 {srt_ctrl_pkts_nak_cnt:>26}")

		print(
			f"- Recovered pkts (lost-dropped)   {srt_data_rexmits.count():>26}"
			f" {to_percent(srt_data_rexmits.count(), data_pkts_org_received_lost):>8}%"
			"  out of original DATA pkts (received+lost)"
		)
		print("  Retransmitted")
		print(f"     once:                        {srt_data_rex_once_cnt:>26} {to_percent(srt_data_rex_once_cnt, data_pkts_org_received_lost):>8}%")
		print(f"     twice:                       {srt_data_rex_twice_cnt:>26} {to_percent(srt_data_rex_twice_cnt, data_pkts_org_received_lost):>8}%")
		print(f"     3×:                          {srt_data_rex_3x_cnt:>26} {to_percent(srt_data_rex_3x_cnt, data_pkts_org_received_lost):>8}%")
		print(f"     4×:                          {srt_data_rex_4x_cnt:>26} {to_percent(srt_data_rex_4x_cnt, data_pkts_org_received_lost):>8}%")
		print(f"     more:                        {srt_data_rex_5x_more_cnt:>26} {to_percent(srt_data_rex_5x_more_cnt, data_pkts_org_received_lost):>8}%")

		print(" Overhead ".center(70, "~"))

		def to_rate(value, duration):
			return round(value * 8 / duration / 1000000, 2)

		sec_begin         = self.srt_packets.iloc[0]['ws.time']
		sec_end           = self.srt_packets.iloc[-1]['ws.time']
		duration_sec      = sec_end - sec_begin

		print(f"- UDP DATA (orig+retrans) rate    {to_rate(self.srt_pkts_data['udp.length'].sum(), duration_sec):>31} Mbps")
		print(f"- SRT DATA (orig+retrans) rate    {to_rate(self.srt_pkts_data['data.len'].sum() + 16 * len(self.srt_pkts_data), duration_sec):>31} Mbps")
		print(f"- SRT DATA (orig+retrans) payload {to_rate(self.srt_pkts_data['data.len'].sum(), duration_sec):>31} Mbps")
		print(f"- UDP DATA (orig) rate            {to_rate(self.srt_pkts_data_org['udp.length'].sum(), duration_sec):>31} Mbps")
		print(f"- SRT DATA (orig) rate            {to_rate(self.srt_pkts_data_org['data.len'].sum() + 16 * len(self.srt_pkts_data_org), duration_sec):>31} Mbps")
		print(f"- SRT DATA (orig) payload         {to_rate(self.srt_pkts_data_org['data.len'].sum(), duration_sec):>31} Mbps")
		print(
			"- SRT DATA (orig) overhead        "
			f"{round(to_rate(self.srt_pkts_data_org['udp.length'].sum(), duration_sec) * 100 / to_rate(self.srt_pkts_data_org['data.len'].sum(), duration_sec) - 100, 2):>31} %"
			"     UDP+SRT headers over SRT payload"
		)


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
def main(path, overwrite):
	"""
	This script parses .pcap or .pcapng tcpdump trace file captured at the receiver side, 
	collects and outputs network traffic statistics.
	"""
	# Process tcpdump trace file and get SRT data packets only
	# (either all data packets or probing packets only)
	pcapng_filepath   = pathlib.Path(path)
	csv_filepath      = convert.convert_to_csv(pcapng_filepath, overwrite)
	
	try:
		srt_packets = extract_packets.extract_srt_packets(csv_filepath)
	except extract_packets.UnexpectedColumnsNumber as error:
		print(
			f'Exception captured: {error} '
			'Please try running the script with --overwrite option.'
		)
		return

	if srt_packets.empty:
		print("No SRT packets found.")
		return

	stats = TrafficStats(srt_packets)
	stats.generate_report()


if __name__ == '__main__':
	main()