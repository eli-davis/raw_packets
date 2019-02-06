""" generate/transmit raw Ethernet packets on the network.

You probably need root privs to be able to bind to the network interface,
e.g.:
    $ sudo python raw.py
"""

import socket
import binascii
import time
import struct
import sys
import os

from termcolor import cprint as print_in_color



#### Ethernet #############################################################

def return_ethernet_packet(mac_dst, mac_src):
    type = [0x08, 0x00]
    ethernet_packet = mac_dst + mac_src + type
    ethernet_packet_str = ""
    for hex_byte in ethernet_packet:
        ethernet_packet_str += chr(hex_byte)
    return ethernet_packet_str

def print_ethernet_packet(ethernet_packet):
    mac_dst = ethernet_packet[0:6]
    mac_src = ethernet_packet[6:12]
    eth_type = ethernet_packet[12:14]
    print("    ETHERNET ({0} bytes)".format(len(ethernet_packet)))
    print("    0x{0} [mac_dst]".format(binascii.hexlify(mac_dst)))
    print("    0x{0} [mac_src]".format(binascii.hexlify(mac_src)))
    print("    0x{0} [eth_type]".format(binascii.hexlify(eth_type)))


#### IP ##################################################################

def return_ip_checksum(data):
    # 16bit one's compliment,
    #     of the one's compliment sum of all 16bit words in the header
    #  set checksum value to zero for purposes of calculating checksum
    sum = 0
    # pick up 16 bits (2 WORDs) every time
    for i in range(0, len(data), 2):
        # Sum up the ordinal of each WORD with
        # network bits order (big-endian)
        if i < len(data) and (i + 1) < len(data):
            sum += ((data[i]) + ((data[i + 1]) << 8))
        elif i < len(data) and (i + 1) == len(data):
            sum += (data[i])
    addon_carry = (sum & 0xffff) + (sum >> 16)
    result = (~ addon_carry) & 0xffff
    # swap bytes
    byte_one = (result & 0xFF)
    byte_two = (result >> 8) & 0xFF
    return [byte_one, byte_two]

def add_ip_checksum_to_header(packet):
    packet[10] = 0x00
    packet[11] = 0x00
    checksum = return_ip_checksum(packet)
    packet[10] = checksum[0]
    packet[11] = checksum[1]
    return packet

def add_ip_length_to_header(packet, data_len):
    # length [20 (IP) + 8 (UDP) + len(data)]
    length = 28 + data_len
    packet[2] = (length >> 8) & 0xFF
    packet[3] = length & 0xFF
    return packet

def add_ip_identification_to_header(packet, sequence_number):
    sequence_number = sequence_number & 0xFFFF
    packet[4] = (sequence_number >> 8) & 0xFF
    packet[5] = sequence_number & 0xFF
    return packet

def add_ip_addresses_to_header(packet, src_ip_address, dst_ip_address):
    packet[12:16] = src_ip_address
    packet[16:20] = dst_ip_address
    return packet

def return_ip_packet(src_ip_address, dst_ip_address, data_length, sequence_number):
    ip_packet = [ # IP_version = 4 [bits 0:4]
                  # 32bit_words_in_IP_header = 5 [bits 4:8]
                  0x45,
                  # type of service
                  0x00,
                  # length [20 (IP) + 8 (UDP) + len(data)]
                  0x00, 0x00,
                  # identification (sequence number)
                  0x00, 0x00,
                  # flags / fragment offset
                  0x00, 0x00,
                  # time to live
                  0x01,
                  # protocol = UDP = 17 = 0x11
                  0x11,
                  # IP_header_checksum
                  0x00, 0x00,
                  # source_IP_address
                  # 0x0a, 0x01, 0x21, 0x01,
                  0x00, 0x00, 0x00, 0x00,
                  # destination_IP_address
                  # 0x0a, 0x2a, 0xa0, 0x00 ]
                  0x00, 0x00, 0x00, 0x00 ]
    ip_packet = add_ip_identification_to_header(ip_packet, sequence_number)
    ip_packet = add_ip_length_to_header(ip_packet, data_length)
    ip_packet = add_ip_addresses_to_header(ip_packet, src_ip_address, dst_ip_address)
    ip_packet = add_ip_checksum_to_header(ip_packet)
    # list_of_hex_bytes to str
    ip_packet_str = ""
    for hex_byte in ip_packet:
        ip_packet_str += chr(hex_byte)
    return ip_packet_str

def print_ip_packet(ip_packet):
    a = ip_packet[0:4]
    b = ip_packet[4:8]
    c = ip_packet[8:12]
    ip_addr_src = ip_packet[12:16]
    ip_addr_dst = ip_packet[16:20]
    print("    IP: ({0} bytes)".format(len(ip_packet)))
    print("    0x{0} [ip_version=4/#_32bit_words_in_IP_header=5, ip_type=0, 2byte_length]".format(binascii.hexlify(a)))
    print("    0x{0} [2byte_MSG_ID, 2byte_flags/fragment_offset]".format(binascii.hexlify(b)))
    print("    0x{0} [TTL, UDP_protocol, 2byte_checksum]".format(binascii.hexlify(c)))
    print("    0x{0} [IP_addr_src]".format(binascii.hexlify(ip_addr_src)))
    print("    0x{0} [IP_addr_dst]".format(binascii.hexlify(ip_addr_dst)))

#### UDP #################################################################

def return_udp_packet(src_port, dst_port, data_length):
    udp_packet = [ # source port
                   0x00, 0x00,
                   # destination port
                   0x00, 0x00,
                   # length [8 (UDP) + len(data)]
                   0x00, 0x00,
                   # checksum (not preSEND at the moment)
                   0x00, 0x00 ]
    # add source port
    udp_packet[0] = (src_port >> 8) & 0xFF
    udp_packet[1] = src_port & 0xFF
    # add destination port
    udp_packet[2] = (dst_port >> 8) & 0xFF
    udp_packet[3] = dst_port & 0xFF
    # add length
    length = 8 + data_length
    udp_packet[4] = (length >> 8) & 0xFF
    udp_packet[5] = length & 0xFF
    # list_of_hex_bytes to str
    udp_packet_str = ""
    for hex_byte in udp_packet:
        udp_packet_str += chr(hex_byte)
    return udp_packet_str

def print_udp_packet(udp_packet):
    src_port = udp_packet[0:2]
    dst_port = udp_packet[2:4]
    length   = udp_packet[4:6]
    checksum = udp_packet[6:8]
    print("    UDP: ({0} bytes)".format(len(udp_packet)))
    print("    0x{0} [src_port]".format(binascii.hexlify(src_port)))
    print("    0x{0} [dst_port]".format(binascii.hexlify(dst_port)))
    print("    0x{0} [length]".format(binascii.hexlify(length)))
    print("    0x{0} [checksum]".format(binascii.hexlify(checksum)))



#### PACKET ###########################################################

def return_RIU_mac_address():
    mac_address = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00]
    return mac_address

def return_DELL_mac_address():
    mac_address = [0x00, 0x13, 0x3b, 0x90, 0x7f, 0x07]
    return mac_address

def return_RIU_ip_address():
    ip_address = [0x0a, 0x2a, 0xa0, 0x00]
    return ip_address

def return_DELL_ip_address():
    ip_address = [0x0a, 0x01, 0x21, 0x01]
    return ip_address

def return_packet(mac_dst, mac_src, ip_addr_src, ip_addr_dst, port_src, port_dst, data):

    # sequence number used for IP identification
    if hasattr(return_packet, 'sequence_number') == False:
        return_packet.sequence_number = 1
    else:
        return_packet.sequence_number += 1
        if return_packet.sequence_number > 255:
            return_packet.sequence_number = 1

    ethernet_packet = return_ethernet_packet(mac_dst, mac_src)
    ip_packet       = return_ip_packet(ip_addr_src, ip_addr_dst, len(data), return_packet.sequence_number)
    udp_packet      = return_udp_packet(port_src, port_dst, len(data))


    # min packet length is 60 bytes
    num_bytes_to_add = 0
    num_bytes_in_packet = len(ethernet_packet+ip_packet+udp_packet+data)
    if num_bytes_in_packet < 60:
        num_bytes_to_add = 60 - num_bytes_in_packet
    # add padding if necessary
    padding = ""
    for i in range(0, num_bytes_to_add):
        padding += chr(0x00)

    packet = ""
    packet += ethernet_packet
    packet += ip_packet
    packet += udp_packet
    packet += data
    packet += padding
    return packet


def return_sample_packet(port_dst, data):
    mac_dst = return_RIU_mac_address()
    mac_src = return_DELL_mac_address()
    ip_addr_dst = return_RIU_ip_address()
    ip_addr_src = return_DELL_ip_address()
    port_src = 59
    packet = return_packet(mac_dst, mac_src,
                           ip_addr_src, ip_addr_dst,
                           port_src, port_dst,
                           data)
    return packet



class socket2(object):
    def __init__(self, dst_ip_address, dst_port, src_ip_address, src_port, network_interface):
        # raw send socket bound to network interface (ethernet port)
        self.raw_send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.raw_send_socket.bind((network_interface, 0))
        self.raw_send_socket.settimeout(2)

        # self.dst_port = dst_port
        # udp recv socket listening on port 59
        self.udp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_recv_socket.bind((src_ip_address, src_port))
        self.udp_recv_socket.settimeout(2)

        self.start_time = time.time()

        self.status = ""
        self.bool_awaiting_status_file = False

    def print_time(self, color):
        current_time = time.time()
        time_elapsed = current_time - self.start_time

        _verbose_log_file("    {0:.02} seconds".format(time_elapsed), color)

    def send_data(self, data, port = 59):
        packet = return_RIU_packet(port, data)
        bytes_SEND = self.raw_send_socket.send(packet)
        self.print_time("SEND")
        print_data packet(packet, port)


    def send_ACK(self, block_number, port):
        ACK_str = TFTP.return_ACK_packet(block_number)
        self.send_data(ACK_str, port)

    def recv_data(self):
        try:
            msg, (ip_addr, port) = self.udp_recv_socket.recvfrom(1024)
        except socket.timeout:
            return (TIMEOUT, None, None)
        return msg

def return_RIU_socket():
    dst_ip_address = "10.42.160.0"
    dst_port = 59
    src_ip_address = "10.1.33.1"
    src_port = 59
    network_interface = "enx00133b907f07"
    socket2_object = socket2(dst_ip_address, dst_port, src_ip_address, src_port, network_interface)
    return socket2_object
