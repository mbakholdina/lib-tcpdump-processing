"""
Script designed to collect and output network traffic statistics.
"""
import pathlib

import click

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


@click.command()
@click.argument(
	'path', 
	type=click.Path(exists=True)
)
@click.option(
	'--overwrite/--no-overwrite',
	default=False,
	help=	'If exists, overwrite the .csv file produced out of the .pcapng '
			'tcpdump trace one at the previous iterations of running the script.',
	show_default=True
)
def main(path, overwrite):
	"""
	This script parses .pcapng tcpdump trace file captured at the receiver side, 
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

	sec_begin         = srt_packets.iloc[0]['ws.time']
	sec_end           = srt_packets.iloc[-1]['ws.time']
	duration_sec      = sec_end - sec_begin

	srt_data_i        = (srt_packets['srt.iscontrol'] == 0)
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
	srt_data_lost       = org_seqno_diffs.sum()

	seqnos = srt_packets[srt_data_i]['srt.seqno'].astype('int32').copy()
	seqnos = seqnos.drop_duplicates().sort_values()
	srt_data_pkts_missing = int((seqnos.diff() - 1).sum())

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

	print(f"Overall UDP rate:         {srt_packets[srt_data_i]['udp.length'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data org+rexmit pld:  {srt_packets[srt_data_i]['data.len'].sum() * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data org payload:     {srt_data_org_pld * 8 / duration_sec / 1000000: .3f} Mbps")
	print(f"SRT Data overhead:        {srt_data_org_udp / srt_data_org_pld * 100 - 100: .3f}%")
	print(f"SRT Data org missing:     {srt_data_lost / srt_data_org_count * 100: .3f}%")
	print(f"SRT Data missing (drop):  {srt_data_pkts_missing / srt_data_org_count * 100: .3f}%")
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