"""
Script designed to collect and output network traffic statistics.
"""
import pathlib

import click
import pandas as pd

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


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
		self.time_start = srt_packets.iloc[ 0]['ws.time']
		self.time_stop  = srt_packets.iloc[-1]['ws.time']
		self.duration_sec  = self.time_start - self.time_stop

	def bytes_to_Mbps(self, bytes):
		return bytes * 8 / self.duration_sec / 1000000

	@property
	def srt_data_pkts(self):
		return self.srt_packets[self.index.data_pkts]

	@property
	def srt_data_pkts_org(self):
		return self.srt_packets[self.index.data_pkts_org]

	@property
	def srt_data_pkts_rex(self):
		return self.srt_packets[self.index.data_pkts_rex]

	@property
	def srt_pkts_ctrl(self):
		return self.srt_packets[self.index.ctrl_pkts]

	def generate_report(self):
		# Count the number of packets.
		srt_pkts_cnt          = len(self.srt_packets.index)
		srt_data_pkts_cnt     = self.index.data_pkts.sum()
		srt_data_pkts_org_cnt = self.index.data_pkts_org.sum()
		srt_data_pkts_rex_cnt = self.index.data_pkts_rex.sum()

		srt_ctrl_pkts_cnt        = self.index.ctrl_pkts.sum()
		srt_ctrl_pkts_ack_cnt    = self.index.ctrl_pkts_ack.sum()
		srt_ctrl_pkts_ackack_cnt = self.index.ctrl_pkts_ackack.sum()
		srt_ctrl_pkts_nak_cnt    = self.index.ctrl_pkts_nak.sum()

		# Calculate the number of lost original data packets as the number
		# of original data packets that haven't reached the receiver.
		# Reordered packets are not taken into account, so if a packet is reordered and
		# comes later, it will not be included into statistic.
		seqnos_org = self.srt_data_pkts_org['srt.seqno'].astype('int32')
		# Removing duplicates in received original packets.
		seqnos_org = seqnos_org.drop_duplicates()
		data_pkts_orig_lost_cnt = int((seqnos_org.diff().dropna() - 1).sum())

		# The number of packets considered unrecovered at the receiver.
		# It means nor original, neither retransmitted packet with
		# a particular sequence number hasn't reached the destination.
		seqnos = self.srt_data_pkts['srt.seqno'].astype('int32').copy()
		seqnos = seqnos.drop_duplicates().sort_values()
		data_pkts_unrecovered_cnt = int((seqnos.diff().dropna() - 1).sum())

		# Calculate how much packets were retransmitted once, twice, 3x times, etc.
		# If there was no dropped packets, rexmits = the number of recovered packets
		rexmit_pkts              = self.srt_data_pkts_rex.copy()
		rexmit_pkts['srt.seqno'] = rexmit_pkts['srt.seqno'].astype('int32')
		rexmit_pkts['seqno']     = rexmit_pkts['srt.seqno']
		rexmits                  = rexmit_pkts.groupby(['srt.seqno'])['seqno'].count()
		rex_once_cnt             = rexmits[rexmits == 1].count()
		rex_twice_cnt            = rexmits[rexmits == 2].count()
		rex_3x_cnt               = rexmits[rexmits == 3].count()
		rex_4x_cnt               = rexmits[rexmits == 4].count()
		rex_5x_more_cnt          = rexmits[rexmits > 4].count()

		def to_percent(value, base):
			return round(value / base * 100, 2)

		data_pkts_orig_rcvd_lost_cnt = srt_data_pkts_org_cnt + data_pkts_orig_lost_cnt

		print(" SRT Packets ".center(70, "~"))

		print(f"- SRT DATA+CONTROL pkts           {srt_pkts_cnt:>26}")

		print(f"- SRT DATA pkts                   {srt_data_pkts_cnt:>26}")
		print(
			f"  - Original DATA pkts received   {srt_data_pkts_org_cnt:>26}"
			f" {to_percent(srt_data_pkts_org_cnt, srt_data_pkts_cnt):>8}%"
			"  out of SRT DATA pkts"
		)
		
		print(
			f"  - Retransmitted DATA pkts received       {srt_data_pkts_rex_cnt:>17}"
			f" {to_percent(srt_data_pkts_rex_cnt, srt_data_pkts_cnt):>8}%"
			"  out of SRT DATA pkts"
		)
		rex_5x_more_total = srt_data_pkts_rex_cnt - (rex_once_cnt + rex_twice_cnt * 2 + rex_3x_cnt * 3 + rex_4x_cnt * 4)
		tmp = str(rex_once_cnt) + '(' + str(rex_once_cnt) + ')'
		tmp2 = str(rex_twice_cnt) + '(' + str(rex_twice_cnt * 2) + ')'
		tmp3 = str(rex_3x_cnt) + '(' + str(rex_3x_cnt * 3) + ')'
		tmp4 = str(rex_4x_cnt) + '(' + str(rex_4x_cnt * 4) + ')'
		tmp_more = str(rex_5x_more_cnt) + '(' + str(rex_5x_more_total) + ')'
		print(f"       once:         {tmp:>39} {to_percent(rex_once_cnt, srt_data_pkts_cnt):>8}%")
		print(f"       twice:        {tmp2:>39} {to_percent(rex_twice_cnt * 2, srt_data_pkts_cnt):>8}%")
		print(f"       3×:           {tmp3:>39} {to_percent(rex_3x_cnt * 3, srt_data_pkts_cnt):>8}%")
		print(f"       4×:           {tmp4:>39} {to_percent(rex_4x_cnt * 4, srt_data_pkts_cnt):>8}%")
		print(f"       more:         {tmp_more:>39} {to_percent(rex_5x_more_total, srt_data_pkts_cnt):>8}%")

		print(
			f"  - Original DATA pkts lost       {data_pkts_orig_lost_cnt:>26}"
			f" {to_percent(data_pkts_orig_lost_cnt, data_pkts_orig_rcvd_lost_cnt):>8}%"
			"  out of original DATA pkts (received+lost)"
		)

		print(
			f"  - DATA pkts unrecovered           {data_pkts_unrecovered_cnt:>24}"
			f" {to_percent(data_pkts_unrecovered_cnt, data_pkts_orig_rcvd_lost_cnt):>8}%"
			"  out of original DATA pkts (received+lost)"
		)

		data_pkts_recovered_cnt = data_pkts_orig_lost_cnt - data_pkts_unrecovered_cnt
		print(
			f"  - DATA pkts recovered (lost-unrecovered)   {data_pkts_recovered_cnt:>15}"
			f" {to_percent(data_pkts_recovered_cnt, data_pkts_orig_rcvd_lost_cnt):>8}%"
			"  out of original DATA pkts (received+lost)"
		)

		print(f"- SRT CONTROL pkts                {srt_ctrl_pkts_cnt:>26}")
		print(f"  - ACK pkts sent                 {srt_ctrl_pkts_ack_cnt:>26}")
		print(f"  - ACKACK pkts received          {srt_ctrl_pkts_ackack_cnt:>26}")
		print(f"  - NAK pkts sent                 {srt_ctrl_pkts_nak_cnt:>26}")

		

		

		return

		print(" Traffic ".center(70, "~"))

		def to_rate(value, duration):
			return round(value * 8 / duration / 1000000, 2)

		sec_begin         = self.srt_pkts_data.iloc[0]['ws.time']
		sec_end           = self.srt_pkts_data.iloc[-1]['ws.time']
		duration_sec      = sec_end - sec_begin

		print(f"- SRT DATA pkts")
		print(f"  - SRT payload + SRT hdr + UDP hdr (orig+retrans)  {to_rate(self.srt_pkts_data['udp.length'].sum(), duration_sec):>13} Mbps")
		print(f"  - SRT payload + SRT hdr (orig+retrans)            {to_rate(self.srt_pkts_data['data.len'].sum() + 16 * len(self.srt_pkts_data), duration_sec):>13} Mbps")
		print(f"  - SRT payload (orig+retrans)                      {to_rate(self.srt_pkts_data['data.len'].sum(), duration_sec):>13} Mbps")
		print(f"  - SRT payload + SRT hdr + UDP hdr (orig)          {to_rate(self.srt_pkts_data_org['udp.length'].sum(), duration_sec):>13} Mbps")
		print(f"  - SRT payload + SRT hdr (orig)                    {to_rate(self.srt_pkts_data_org['data.len'].sum() + 16 * len(self.srt_pkts_data_org), duration_sec):>13} Mbps")
		print(f"  - SRT payload (orig)                              {to_rate(self.srt_pkts_data_org['data.len'].sum(), duration_sec):>13} Mbps")
		
		print(" Overhead ".center(70, "~"))

		print(f"- SRT DATA pkts")
		print(
			"  - UDP+SRT headers over SRT payload (orig)"
			f"{round(to_rate(self.srt_pkts_data_org['udp.length'].sum(), duration_sec) * 100 / to_rate(self.srt_pkts_data_org['data.len'].sum(), duration_sec) - 100, 2):>25} %"
		)
		print(
			"  - Retransmitted over received(orig)+missing pkts"
			f"{round(srt_data_pkts_rex_cnt * 100 / (srt_data_pkts_org_cnt + srt_data_pkts_missing), 2):>18} %"
		)

		print(" Notations ".center(70, "~"))
		print("pkts - packets")
		print("hdr - header")
		print("orig - original")
		print("retrans - retransmitted")

		print("".center(70, "~"))

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