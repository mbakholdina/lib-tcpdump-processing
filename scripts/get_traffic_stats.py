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

		return


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
	return

	sec_begin         = srt_packets.iloc[0]['ws.time']
	sec_end           = srt_packets.iloc[-1]['ws.time']
	duration_sec      = sec_end - sec_begin

	def bytes_to_Mbps(bytes):
		return bytes * 8 / duration_sec / 1000000

	# Index
	srt_data_i        = (srt_packets['srt.iscontrol'] == 0)
	srt_control_i     = (srt_packets['srt.iscontrol'] == 1)
	srt_data_org_i    = srt_data_i & (srt_packets['srt.msg.rexmit'] == 0)
	srt_data_rexmit_i = srt_data_i & (srt_packets['srt.msg.rexmit'] == 1)
	srt_ack_i         = (~srt_data_i) & (srt_packets['srt.type'] == '0x00000002')
	srt_ackack_i      = (~srt_data_i) & (srt_packets['srt.type'] == '0x00000006')
	srt_nak_i         = (~srt_data_i) & (srt_packets['srt.type'] == '0x00000003')

	srt_data_org_pld  = srt_packets[srt_data_org_i]['data.len'].sum()
	srt_data_org_udp  = srt_packets[srt_data_org_i]['udp.length'].sum()
	srt_data_rex_udp  = srt_packets[srt_data_rexmit_i]['udp.length'].sum()
	srt_ack_udp       = srt_packets[srt_ack_i]['udp.length'].sum()
	srt_ackack_udp    = srt_packets[srt_ackack_i]['udp.length'].sum()
	srt_nak_udp       = srt_packets[srt_nak_i]['udp.length'].sum()

	srt_data_org_seqnos = srt_packets[srt_data_org_i]['srt.seqno']
	org_seqno_diffs     = srt_data_org_seqnos.diff() - 1
	srt_data_pkts_org_lost       = int(org_seqno_diffs.sum())

	srt_data_pkts       = srt_packets[srt_data_i].copy()



	srt_data_pkts['srt.seqno']      = srt_data_pkts['srt.seqno'].astype('int32')
	srt_data_pkts['seqno']          = srt_data_pkts['srt.seqno']
	srt_data_seqnos     = srt_data_pkts.groupby(['srt.seqno'])['seqno'].count()
	print(srt_data_seqnos)
	data_seqno_diffs   = srt_data_seqnos.diff() - 1
	print(data_seqno_diffs)
	#srt_data_rex_once_count       = srt_data_rexmits[srt_data_rexmits == 1].count()

	#srt_data_seqnos    = srt_packets[srt_data_i]['srt.seqno'].drop_duplicates()
	#print(srt_data_seqnos)
	#data_seqno_diffs   = srt_data_seqnos.diff() - 1
	srt_data_pkts_missing = int(data_seqno_diffs.sum())

	srt_data_org_count = srt_packets[srt_data_org_i]['udp.length'].count()
	srt_data_rex_count = srt_packets[srt_data_rexmit_i]['udp.length'].count()

	rexmit_pkts                   = srt_packets[srt_data_rexmit_i].copy()
	rexmit_pkts['srt.seqno']      = rexmit_pkts['srt.seqno'].astype('int32')
	rexmit_pkts['seqno']          = rexmit_pkts['srt.seqno']
	srt_data_rexmits              = rexmit_pkts.groupby(['srt.seqno'])['seqno'].count()
	srt_data_rex_once_count       = srt_data_rexmits[srt_data_rexmits == 1].count()
	srt_data_rex_twice_count      = srt_data_rexmits[srt_data_rexmits == 2].count()
	srt_data_rex_3x_count         = srt_data_rexmits[srt_data_rexmits == 3].count()
	srt_data_rex_4x_count         = srt_data_rexmits[srt_data_rexmits == 4].count()
	srt_data_rex_5x_more_count    = srt_data_rexmits[srt_data_rexmits > 4].count()

	# IPv4_HDR_BYTES       = 20
	UDP_HDR_BYTES          =  8
	srt_pkts_cnt           = len(srt_packets.index)
	srt_data_pkts_cnt      = len(srt_data_i)
	srt_data_pkts_org_cnt  = len(srt_data_org_i)
	srt_data_pkts_rex_cnt  = len(srt_data_rexmit_i)
	udp_pkts_len_sum       = srt_packets['udp.length'].sum()
	udp_data_pkts_len_sum  = srt_packets[srt_data_i]['udp.length'].sum()
	udp_ctrl_pkts_len_sum  = srt_packets[srt_control_i]['udp.length'].sum()

	# Data packets section
	data_pkts_org_udplen_sum    = srt_packets[srt_data_org_i]['udp.length'].sum()
	data_pkts_rexmit_udplen_sum = srt_packets[srt_data_rexmit_i]['udp.length'].sum()

	# Control packets section
	ctrl_pkts_ack_udplen_sum = srt_packets[srt_ack_i]['udp.length'].sum()
	ctrl_pkts_nak_udplen_sum = srt_packets[srt_nak_i]['udp.length'].sum()
	ctrl_pkts_ackack_udplen_sum = srt_packets[srt_ackack_i]['udp.length'].sum()
	
	print(f"Overall rate with UDP headers:   {bytes_to_Mbps(udp_pkts_len_sum): .3f} Mbps")
	print(f"- SRT DATA pkts rate:            {bytes_to_Mbps(udp_data_pkts_len_sum): .3f} Mbps")
	print(f"  - ORG DATA pkts rate:          {bytes_to_Mbps(data_pkts_org_udplen_sum): .3f} Mbps")
	print(f"  - REXMIT DATA pkts rate:       {bytes_to_Mbps(data_pkts_rexmit_udplen_sum): .3f} Mbps")
	print(f"- SRT CTRL pkts rate:            {bytes_to_Mbps(udp_ctrl_pkts_len_sum): .3f} Mbps")
	print(f"  - ACK pkts rate:               {bytes_to_Mbps(ctrl_pkts_ack_udplen_sum): .3f} Mbps")
	print(f"  - NAK pkts rate:               {bytes_to_Mbps(ctrl_pkts_nak_udplen_sum): .3f} Mbps")
	print(f"  - ACKACK pkts rate:            {bytes_to_Mbps(ctrl_pkts_ackack_udplen_sum): .3f} Mbps")
	print("")
	print(f"SRT packets:                      {srt_pkts_cnt}")
	print(f"- SRT DATA pkts:                  {srt_data_pkts_cnt}")
	print(f"  - SRT ORG DATA pkts:            {srt_data_pkts_org_cnt}")
	print(f"  - SRT ORG DATA pkts lost:       {srt_data_pkts_org_lost}")
	print(f"  - SRT REXMIT DATA pkts:         {srt_data_pkts_rex_cnt}")
	print(f"  - SRT DATA pkts missing (drop): {srt_data_pkts_missing}")
	print("")
	print(f"SRT overhead with UDP headers:    {bytes_to_Mbps(0): .3f} Mbps")

	return

	srt_data_pkts_cnt      = len(srt_data_i)
	srt_ctrl_pkts_cnt      = len(srt_control_i)
	srt_data_pkts_len_sum  = srt_packets[srt_data_i]['data.len'].sum()
	srt_ctrl_pkts_len_sum  = srt_packets[srt_control_i]['data.len'].sum()
	print(f"Overall SRT rate (with SRT hdrs):     {bytes_to_Mbps(udp_pkts_len_sum - srt_pkts_cnt * UDP_HDR_BYTES): .3f} Mbps")
	print(f"  SRT DATA pkts rate (with SRT hdrs): {bytes_to_Mbps(udp_data_pkts_len_sum - srt_data_pkts_cnt * UDP_HDR_BYTES): .3f} Mbps")
	print(f"  SRT CTRL pkts rate (with SRT hdrs): {bytes_to_Mbps(srt_ctrl_pkts_len_sum - srt_ctrl_pkts_cnt * UDP_HDR_BYTES): .3f} Mbps")

	print(f"Overall SRT rate (with SRT hdrs):     {bytes_to_Mbps(udp_pkts_len_sum - srt_pkts_cnt * UDP_HDR_BYTES): .3f} Mbps")

	print(f"  Data payload (org + rexmit):  {bytes_to_Mbps(srt_data_pkts_len_sum): .3f} Mbps")
	print(f"  Data payload (org):  {srt_packets[srt_data_i]['data.len'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"  Data payload (rexmit):  {srt_packets[srt_data_i]['data.len'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")

	#### old

	print(f"Overall UDP rate:         {srt_packets[srt_data_i]['udp.length'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	#print(f"Overall SRT rate:         {srt_packets[srt_data_i]['udp.length'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data org+rexmit pld:  {srt_packets[srt_data_i]['data.len'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data org payload:     {srt_data_org_pld * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data overhead:        {srt_data_org_udp / srt_data_org_pld * 100 - 100: .3f}%")
	print(f"SRT Data org missing:     {srt_data_lost / srt_data_org_count * 100: .3f}%")
	print(f"SRT Data rexmit overhead: {srt_data_rex_udp / srt_data_org_pld * 100: .3f}%")
	print(f"SRT ACK overhead:         {srt_ack_udp / srt_data_org_pld * 100: .3f}%")
	print(f"SRT ACKACK overhead:      {srt_ack_udp / srt_data_org_pld * 100: .3f}%")
	print(f"SRT NAK overhead:         {srt_nak_udp / srt_data_org_pld * 100: .3f}%")

	print("===========================================")
	srt_overhead_bytes = srt_data_rex_udp + srt_ack_udp + srt_ackack_udp + srt_nak_udp
	print(f"SRT overall overhead:      {srt_overhead_bytes / srt_data_org_pld * 100: .3f}%")
	print(f"SRT Data packets (org):     {srt_data_org_count}")
	print(f"SRT retransmitted:          {srt_data_rexmits.count()} packets ({srt_data_rex_count} retransmissions)")
	print(f"SRT DATA retransmisions:   {srt_data_rex_count / srt_data_org_count * 100: .3f}% × DATA packets")
	print(f"SRT retransmitted:         {srt_data_rexmits.count() / srt_data_org_count * 100: .3f}% of original packets")
	#print("Retransmitted = 1x Number once + 2x Number twice + Xx more")
	print(f"    including retransmitted:")
	print(f"    once:   {srt_data_rex_once_count / srt_data_org_count * 100: .3f}% of original packets")
	print(f"    twice:  {srt_data_rex_twice_count / srt_data_org_count * 100: .3f}% of original packets")
	print(f"    3×:     {srt_data_rex_3x_count / srt_data_org_count * 100: .3f}% of original packets")
	print(f"    4×:     {srt_data_rex_4x_count / srt_data_org_count * 100: .3f}% of original packets")
	print(f"    more:   {srt_data_rex_5x_more_count / srt_data_org_count * 100: .3f}% of original packets")

	# TODO: add an option to print packets retransmitted more than once
	#print(srt_data_rexmits.loc[47383194])
	#print(srt_data_rexmits[srt_data_rexmits > 1])


if __name__ == '__main__':
	main()