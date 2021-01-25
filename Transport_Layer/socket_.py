from struct import *
import struct as struct
import sys
import socket

class socket_sniffer():
    def __init__(self, source_port):
        self.source_port = source_port
    
    def sniff_packets(self, sk):
        #this function will get the packets from the
        #source port
        raw_data, addr = sk.recvfrom(self.source_port)
        ethernet_frame_ = self.decapsulation_Datalink(raw_data)
        ipv4_ = self.decapsulation_ipv4_header(ethernet_frame_.data)
        return ethernet_frame_, ipv4_, ipv4_.data 

    def decapsulation_Datalink(self, raw_data):
        dest, src, protoype = struct.unpack('! 6s 6s H', raw_data[:14])
        data = raw_data[14:]
        ethernet_frame_ = ethernet_frame(dest, src, protoype, data)
        return ethernet_frame_
    
    def decapsulation_ipv4_header(self, raw_data):
        version_header_length = raw_data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl , proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        data = raw_data[header_length:]
        ipv4_ = ipv4(version, header_length, ttl, proto, src, target, data) 
        return ipv4_

    def decapsulation_udp_header(self, raw_data):
        pass


class ethernet_frame():
    def __init__(self, destination_mac, source_mac, protocol, data):
        self.destination_mac = destination_mac
        self.source_mac = source_mac
        self.protocol = protocol
        self.data = data

class ipv4():
    def __init__(self, ver, ihl, ttl, protocol, \
         header_checksum, source_ip, destination_ip, data, \
              tos=None, len_=None, flags=None, identification=None):
              self.ver = ver.to_bytes(1, type="little") #protocol version
              self.ihl = ihl.to_bytes(1, type="little") #header lenght
              self.tos = tos.to_bytes(1, type="little") #type of service
              self.len_ = len_.to_bytes(2, type="little") #total lenght
              self.identification = identification.to_bytes(2, type="little")
              self.flags = flags.to_bytes(1, type="little") #flags
              self.ttl = ttl.to_bytes(1, type="little") #time to live
              self.protocol = protocol.to_bytes(1, type="little") 
              self.header_checksum = header_checksum.to_bytes(2, type="little")
              self.source_ip = source_ip.to_bytes(4, type="little")
              self.destination_ip = destination_ip.to_bytes(4, type="little")
              self.data = data
              self.ipv4_packet = self.ver + self.ihl + self.tos + self.len_ + self.identification + self.identification + self.flags + \
                  self.ttl + self.protocol + self.header_checksum + self.source_ip + \
                      self.destination_ip + self.data
              self.ipv4_header = self.ver + self.ihl + self.tos + self.len_ + self.identification + self.flags + \
                  self.ttl + self.protocol + self.header_checksum + self.source_ip + \
                      self.destination_ip

    def set_ip_host(self):
        #this function will set the public network ip
        self.source_ip = socket.gethostbyname(socket.gethostname()).to_bytes(4, type="little")

    def set_checksum(self):
        s = 0
        for i in range(0, len(self.ipv4_header), 2):
            w = ord(self.ipv4_header[i]) + (ord(self.ipv4_header[i+1]) << 8)
            s = self.carry_around_add(s, w)
        self.header_checksum =  ~s & 0xffff

    def carry_around_add(self, a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)
    
    def set_length(self):
        self.len_ = 3



class socketSever():
    def __init__(self, port_number):
        self.port_number = port_number
        # the public network interface
        self.source_ip = socket.gethostbyname(socket.gethostname()) 

    def create_socket_udp_sniffer(self):
        sk = socket_sniffer(self.port_number)
        s = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        return sk.sniff_packets(s)
    