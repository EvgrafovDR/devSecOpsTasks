import os

from scapy.layers.inet import TCP, IP
from scapy.utils import PcapReader
import texttable


def find_syn_packets(file_path):
    """
    Return list of syn packets

    :param file_path: string
    :return: list
    """
    result = []
    tcpdump = PcapReader(file_path)
    for pkt in tcpdump:
        if TCP in pkt:
            if pkt[TCP].flags == "S":
                result.append(pkt)
    return result


def get_fields_dict(packet):
    return {
        "L2": packet.fields,
        "L3": packet[IP].fields,
        "L4": packet[TCP].fields,
    }


def append_to_result(result, fields_dict, packets_count):
    # Обрабатываем существующие в результате поля
    for layer, fields in result.items():
        for key, field_list in fields.items():
            if key in fields_dict[layer].keys():
                field_list.append(fields_dict[layer][key])
            else:
                field_list.append(None)
    # Добавляем новые поля
    for layer, fields in fields_dict.items():
        for key, field in fields.items():
            if key not in result[layer].keys():
                result[layer][key] = []
                for i in range(0, packets_count):
                    result[layer][key].append(None)
                result[layer][key].append(field)
    return result


def packets_fields(packets):
    """
    Make table of fields for N packets

    :param packets: list
    """
    result = {
        "L2": {},
        "L3": {},
        "L4": {},
    }
    packet_num = 0
    for packet in packets:
        fields_dict = get_fields_dict(packet)
        result = append_to_result(result, fields_dict, packet_num)
        packet_num += 1
    return packet_num, result


def print_table(fields_dict, packet_count):
    tab = texttable.Texttable()
    headings = ["Layer", "Field"]
    for i in range(0, packet_count):
        headings.append("Packet %d" % (i+1))
    tab.header(headings)
    for layer, fields in fields_dict.items():
        for field, values in fields.items():
            # Проверяем, все ли элементы массива идентичны
            if values.count(values[0]) != len(values):
                tab.add_row([layer, field] + values)
    text_table = tab.draw()
    print(text_table)


def dialog():
    packets = []
    dump_path = input("Enter dump path (press enter to continue):")
    while dump_path:
        if os.path.isfile(dump_path):
            syn_packets = find_syn_packets(dump_path)
            if len(syn_packets) == 0:
                print("Not found any SYN packet in %s" % dump_path)
            else:
                i = 0
                for syn_packet in syn_packets:
                    i += 1
                    print("%d. %s:%d -> %s:%d" % (i, syn_packet[IP].src, syn_packet[IP].sport, syn_packet[IP].dst, syn_packet[IP].dport))
                chosen_num = int(input("Choose one packet [%d-%d]:" % (1, i)))
                packets.append(syn_packets[chosen_num-1])
                print("Packets count is %d" % len(packets))
        else:
            print("File not exists, try again...")
        dump_path = input("Enter dump path (press enter to continue):")
    packet_num, fields = packets_fields(packets)
    print_table(fields, packet_num)


if __name__ == "__main__":
    dialog()