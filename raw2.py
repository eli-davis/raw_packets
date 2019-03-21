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

def return_ethernet_header(mac_dst, mac_src):
    type = [0x08, 0x00]
    ethernet_header = mac_dst + mac_src + type
    ethernet_header_str = ""
    for hex_byte in ethernet_header:
        ethernet_header_str += chr(hex_byte)
    return ethernet_header_str

def print_ethernet_header(ethernet_header):
    mac_dst = ethernet_header[0:6]
    mac_src = ethernet_header[6:12]
    eth_type = ethernet_header[12:14]
    print("    ETHERNET ({0} bytes)".format(len(ethernet_header)))
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

def return_ip_header(src_ip_address, dst_ip_address, data_length, sequence_number):
    ip_header = [ # IP_version = 4 [bits 0:4]
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
    ip_header = add_ip_identification_to_header(ip_header, sequence_number)
    ip_header = add_ip_length_to_header(ip_header, data_length)
    ip_header = add_ip_addresses_to_header(ip_header, src_ip_address, dst_ip_address)
    ip_header = add_ip_checksum_to_header(ip_header)
    # list_of_hex_bytes to str
    ip_header_str = ""
    for hex_byte in ip_header:
        ip_header_str += chr(hex_byte)
    return ip_header_str

def print_ip_header(ip_header):
    a = ip_header[0:4]
    b = ip_header[4:8]
    c = ip_header[8:12]
    ip_addr_src = ip_header[12:16]
    ip_addr_dst = ip_header[16:20]

    length = ip_header[2:4]
    (int_length,) = struct.unpack(">H", length)

    print("    IP: ({0} bytes)".format(len(ip_header)))
    print("    0x{0} [ip_version=4/#_32bit_words_in_IP_header=5, ip_type=0, 2byte_length]".format(binascii.hexlify(a)))
    print("    0x{0} [2byte_MSG_ID, 2byte_flags/fragment_offset]".format(binascii.hexlify(b)))
    print("    0x{0} [TTL, UDP_protocol, 2byte_checksum]".format(binascii.hexlify(c)))
    print("    0x{0} [IP_addr_src]".format(binascii.hexlify(ip_addr_src)))
    print("    0x{0} [IP_addr_dst]".format(binascii.hexlify(ip_addr_dst)))
    print("    0x{0} [length] ({1} bytes)".format(binascii.hexlify(length), int_length))

#### UDP #################################################################

def return_udp_header(src_port, dst_port, data_length):
    udp_header = [ # source port
                   0x00, 0x00,
                   # destination port
                   0x00, 0x00,
                   # length [8 (UDP) + len(data)]
                   0x00, 0x00,
                   # checksum (not preSEND at the moment)
                   0x00, 0x00 ]
    # add source port
    udp_header[0] = (src_port >> 8) & 0xFF
    udp_header[1] = src_port & 0xFF
    # add destination port
    udp_header[2] = (dst_port >> 8) & 0xFF
    udp_header[3] = dst_port & 0xFF
    # add length
    length = 8 + data_length
    udp_header[4] = (length >> 8) & 0xFF
    udp_header[5] = length & 0xFF
    # list_of_hex_bytes to str
    udp_header_str = ""
    for hex_byte in udp_header:
        udp_header_str += chr(hex_byte)
    return udp_header_str

def print_udp_header(udp_header):
    src_port = udp_header[0:2]
    dst_port = udp_header[2:4]
    length   = udp_header[4:6]
    checksum = udp_header[6:8]

    (int_src_port,) = struct.unpack(">H", src_port)
    (int_dst_port,) = struct.unpack(">H", dst_port)
    (int_length,) = struct.unpack(">H", length)

    print("    UDP: ({0} bytes)".format(len(udp_header)))
    print("    0x{0} [src_port] ({1})".format(binascii.hexlify(src_port), int_src_port))
    print("    0x{0} [dst_port] ({1})".format(binascii.hexlify(dst_port), int_dst_port))
    print("    0x{0} [length] ({1} bytes)".format(binascii.hexlify(length), int_length))
    print("    0x{0} [checksum]".format(binascii.hexlify(checksum)))



#### PACKET ###########################################################

def return_RIU_mac_address():
    # mac_address = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00]
    mac_address = [0xfc, 0x69, 0x47, 0xdf, 0xbb, 0xa1]
    return mac_address

def return_DELL_mac_address():
    # mac_address = [0x00, 0x13, 0x3b, 0x90, 0x7f, 0x07]
    mac_address = [0x00, 0xe0, 0x4c, 0xa2, 0xdd, 0xa0]
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

    ethernet_header = return_ethernet_header(mac_dst, mac_src)
    ip_header       = return_ip_header(ip_addr_src, ip_addr_dst, len(data), return_packet.sequence_number)
    udp_header      = return_udp_header(port_src, port_dst, len(data))


    # min packet length is 60 bytes
    num_bytes_to_add = 0
    num_bytes_in_packet = len(ethernet_header+ip_header+udp_header+data)
    if num_bytes_in_packet < 60:
        num_bytes_to_add = 60 - num_bytes_in_packet
    # add padding if necessary
    padding = ""
    for i in range(0, num_bytes_to_add):
        padding += chr(0x00)

    packet = ""
    packet += ethernet_header
    packet += ip_header
    packet += udp_header
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



class network_interface_socket(object):
    def __init__(self, network_interface):
        # raw send socket bound to network interface (ethernet port)
        ETH_P_ALL = 3
        self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.raw_socket.bind((network_interface, 0))
        self.raw_socket.settimeout(2)

        # self.dst_port = dst_port
        # udp recv socket listening on port
        #### self.udp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #### self.udp_recv_socket.bind((src_ip_address, src_port))
        #### self.udp_recv_socket.settimeout(2)

        self.start_time = time.time()

        # self.FILE = open("channel_2B_60seconds.txt", "w")


    def print_timestamped_msg(self, msg, color="red"):
        current_time = time.time()
        time_elapsed = current_time - self.start_time
        if time_elapsed >= 60:
            self.FILE.close()
            sys.exit()

        ethernet_header = msg[0:14]
        ip_header = msg[14:34]
        udp_header = msg[34:42]
        data = msg[42:]

        #print_ethernet_header(ethernet_header)
        #print_ip_header(ip_header)
        #print_udp_header(udp_header)
        #print("    DATA: ({0} bytes)".format(len(data)))


        hex_msg = binascii.hexlify(msg)
        # self.FILE.write("{0:.09}: {1}\n".format(time_elapsed, hex_msg))

        # print_in_color("    {0:.02}: {1}".format(time_elapsed, hex_msg), color)
        # print_in_color("    {0}: {1}".format(time_elapsed, hex_data), color)
        print_in_color("{0:.09}: ".format(time_elapsed), "cyan")


    def send_data(self, data, port = 59):
        packet = return_sample_packet(port, data)
        N_bytes_sent = self.raw_socket.send(packet)
        # self.print_time("SEND")
        # print_data packet(packet, port


    '''
    def send_ACK(self, block_number, port):
        ACK_str = TFTP.return_ACK_packet(block_number)
        self.send_data(ACK_str, port)
    '''

    def recv_data(self):
        try:
            msg = self.raw_socket.recv(1024)
            #print("RECV MSG")
            self.print_timestamped_msg(msg)
        except socket.timeout:
            print("NO MSG")
            return None
        return msg


# network_interface = "enx1491823ba3e0"
network_interface = "enx00e04ca2dda0"
socket_handle = network_interface_socket(network_interface)

'''
while True:
    socket_handle.send_data("Hiey =d")
    time.sleep(0.01)
'''

def send_on_channel_over_one_second(list_of_messages_on_disc):
    start_time = time.time()
    for msg_on_disc in list_of_messages_on_disc:
        msg_on_disc = msg_on_disc.strip()
        split_msg = msg_on_disc.split(": ")
        timestamp = float(split_msg[0])
        hex_msg = split_msg[1]
        msg = binascii.unhexlify(hex_msg)


        #elapsed_time = time.time() - start_time
        #if elapsed_time < timestamp:
        #    #elapsed_time = time.time() - start_time
        #    wait_time = timestamp - elapsed_time
        #    time.sleep(wait_time)


        #print(timestamp)
        #print(hex_msg)
        socket_handle.send_data(msg)

        #print("_________________________________________________")
    end_time = time.time()
    delta_t = end_time - start_time
    print("delta_t={0}".format(delta_t))
    print("N_messages={0}".format(len(list_of_messages_on_disc)))
    #print("N_bytes={0}".format(len(list_of_messages_on_disc)))

if __name__ == "__main__":
    FILE = open("channel_1A_1seconds.txt", "r")
    list_of_messages_on_disc = FILE.readlines()
    FILE.close()

    while True:
        send_on_channel_over_one_second(list_of_messages_on_disc)
