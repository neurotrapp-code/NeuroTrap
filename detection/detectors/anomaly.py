"""Protocol-anomaly detector: NULL/FIN/Xmas scans and SYN+FIN combos."""
# TCP flag bits: FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20


def detect_flag_anomaly(src_ip, dst_port, flags: int):
    f = int(flags)
    label = None
    if f == 0x00:
        label = "null_scan"
    elif f == 0x01:
        label = "fin_scan"
    elif f & 0x01 and f & 0x02:           # SYN+FIN
        label = "syn_fin"
    elif f & 0x29 == 0x29:                # FIN+PSH+URG = Xmas
        label = "xmas_scan"
    if label:
        return {
            "attack_type": "protocol_anomaly",
            "severity": "medium",
            "src_ip": src_ip,
            "dst_port": dst_port,
            "detail": label,
        }
    return None
