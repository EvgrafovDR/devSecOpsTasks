import texttable
from scapy.layers.inet import TCP, IP
from scapy.utils import PcapReader


def check_session(pkt1, pkt2):
    outgoing = pkt1.src == pkt2.src and pkt1[IP].sport == pkt2[IP].sport \
               and pkt1.dst == pkt2.dst and pkt1[IP].dport == pkt2[IP].dport
    incoming = pkt1.src == pkt2.dst and pkt1[IP].sport == pkt2[IP].dport \
               and pkt1.dst == pkt2.src and pkt1[IP].dport == pkt2[IP].sport
    return outgoing or incoming


def get_tcp_sessions(file_path):
    tcpdump = PcapReader(file_path)
    sessions = []
    for pkt in tcpdump:
        if TCP in pkt and pkt[TCP].flags & 2:
            # TCP SYN packet aka session start
            sessions.append({"start_pkt": pkt, "size": len(pkt), "count": 1, "start_time": pkt.time, "end_time": pkt.time})
        else:
            for session in sessions:
                start_pkt = session["start_pkt"]
                if IP in pkt:
                    if check_session(pkt, start_pkt):
                        session["size"] += len(pkt)
                        session["count"] += 1
                        session["end_time"] = pkt.time
    return sessions


def print_table(sessions):
    tab = texttable.Texttable()
    headings = ["Source", "Destination", "Size", "Packets", "Duration"]
    tab.header(headings)
    for session in sessions:
        tab.add_row([
            "%s:%d" % (session["start_pkt"][IP].src, session["start_pkt"][IP].sport),
            "%s:%d" % (session["start_pkt"][IP].dst, session["start_pkt"][IP].dport),
            session["size"],
            session["count"],
            session["end_time"] - session["start_time"],
        ])
    text_table = tab.draw()
    print(text_table)


def dialog():
    dump_path = input("Enter tcp dump path:")
    sessions = get_tcp_sessions(dump_path)
    print_table(sessions)


if __name__ == "__main__":
    dialog()