from struct import *
import struct 
import sys
import socket
import uuid 

class socket_sniffer():
    def __init__(self, source_port):
        self.source_port = source_port
    
    def sniff_packets(self, sk):
        #this function will get the packets from the
        #source port
        raw_data, addr = sk.recvfrom(self.source_port)
        ethernet_frame_ = self.decapsulation_Datalink(raw_data)
        ipv4_ = self.decapsulation_ipv4_header(ethernet_frame_.data)
        
        if(int.from_bytes(ipv4_.protocol, byteorder=sys.byteorder) == 17):
            return ethernet_frame_, ipv4_, ipv4_.data 
        else:
            return None

    def decapsulation_Datalink(self, raw_data):
        #this function will get the ethernet frame
        dest, src, protoype = struct.unpack('! 6s 6s H', raw_data[:14])
        data = raw_data[14:]
        ethernet_frame_ = ethernet_frame(int.from_bytes(dest, byteorder="little"), int.from_bytes(src, byteorder="little") \
            , protoype, data)
        return ethernet_frame_
    
    def decapsulation_ipv4_header(self, raw_data):
        #this function will get the ipv4 header
        version_header_length = raw_data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl , proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        data = raw_data[header_length:]
        ipv4_ = ipv4_header(version, header_length, ttl, proto, int.from_bytes(src, byteorder="little"),\
            int.from_bytes(target, byteorder="little"), data) 
        return ipv4_

    def decapsulation_udp_header(self, raw_data):
        pass


class ethernet_frame():
    def __init__(self, destination_mac, source_mac, protocol, data):
        self.destination_mac = (destination_mac).to_bytes(6, byteorder="little")
        
        self.source_mac = (source_mac).to_bytes(6, byteorder="little")
        self.protocol = (protocol).to_bytes(2, byteorder="little")
        self.data = data

        self.packet = self.destination_mac + self.source_mac + self.protocol +\
            self.data
    
    def set_packet(self):
        #set the packet again
        self.packet = self.destination_mac + self.source_mac + self.protocol +\
            self.data

    @staticmethod
    def encapsulation_packet(ip_packets, destination_mac):
        #this function add the ethenet frame
        packets_list = []
        for packet in ip_packets:
            eth = ethernet_frame(destination_mac, 0, 0, packet)
            packets_list.append(eth.packet)
        return packets_list

    def set_host_source_mac(self):
        pass

class ipv4_header():
    def __init__(self, ver, ihl, ttl, protocol, \
         source_ip, destination_ip, data, \
              tos=0, len_=0, flags=0, identification=0, offset=0, header_checksum=0):
              self.ver = ver #protocol version
              self.ihl = ihl #header lenght
              self.tos = (tos).to_bytes(1, byteorder="little") #type of service
              self.len_ = (len_).to_bytes(2, byteorder="little") #total lenght
              self.identification = identification.to_bytes(2, byteorder="little")
              self.flags = flags #flags
              self.offset = offset #fragmentation offset
              self.ttl = (ttl).to_bytes(1, byteorder="little") #time to live
              self.protocol = (protocol).to_bytes(1, byteorder="little") 
              self.header_checksum = (header_checksum).to_bytes(2, byteorder="little")
              self.source_ip = (source_ip).to_bytes(4, byteorder="little")
              self.destination_ip = (destination_ip).to_bytes(4, byteorder="little")
              self.data = data
             
              self.ipv4_packet = ((self.ver << 4) + self.ihl).to_bytes(1, byteorder="little") + self.tos + self.len_ + \
                  self.identification + self.identification + ((self.flags << 13) + self.offset).to_bytes(2,byteorder="little") + \
                  self.ttl + self.protocol + self.header_checksum + self.source_ip + self.destination_ip + self.data
              
              self.ipv4_header = ((self.ver << 4) + self.ihl).to_bytes(1, byteorder="little") + self.tos + self.len_ + \
                  self.identification + self.identification + ((self.flags << 13) + self.offset).to_bytes(2,byteorder="little") + \
                  self.ttl + self.protocol + self.header_checksum + self.source_ip + self.destination_ip

    def set_ip_host(self):
        #this function will set the public network ip
        self.source_ip = socket.gethostbyname(socket.gethostname()).to_bytes(4, byteorder="little")
    
    def set_ipv4_packet(self):
        #set the packet 
        self.ipv4_packet = ((self.ver << 4) + self.ihl).to_bytes(1, byteorder="little") + self.tos + self.len_ + \
                  self.identification + self.identification + ((self.flags << 13) + self.offset).to_bytes(2,byteorder="little") + \
                  self.ttl + self.protocol + self.header_checksum + self.source_ip + self.destination_ip + self.data

        
class ipv4():
    @staticmethod
    def send_packets(ip_packets, destination_mac):
        #encapsulation ethernet header
        packet_list = ethernet_frame.encapsulation_packet(ip_packets, destination_mac)
        socketSever.create_socket_send(packet_list)
    
    @staticmethod
    def encapsultion_udp_datagram(udp_datagrams, destination_ip):
        #encapusulation of udp datagrams into ipv4 packets
        ipv4_packet= []
        for i, datagram in enumerate(udp_datagrams):
            ipv4_ = ipv4_header(4, 5, 128, 17, 0, destination_ip, datagram, 0, 0, 0, i, 0, 0)
            ipv4_.set_checksum()
            ipv4_.set_length()
            ipv4_packet.append(ipv4_.ipv4_packet)
        return ipv4_packet
        
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
        #set the toatl length of the packet
        self.len_ = 20 + len(self.data)


class socketSever():
    def __init__(self, port_number):
        self.port_number = port_number
        # the public network interface
        self.source_ip = socket.gethostbyname(socket.gethostname()) 
        self.socket_ = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

    def create_socket_udp_sniffer(self):
        sk = socket_sniffer(self.port_number)
        tuple_headers = sk.sniff_packets(self.socket_)
        if(tuple_headers!= None):
            eht_, ipv4_, udp_packet = tuple_headers
            return eht_,ipv4_, udp_packet
        return None 
    
    def create_socket_send(self, packets):
        s = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        #send all the packets
        for packet in packets:
            s.send(packet)

sk = socketSever(5656)

while True:
    tuple_headers = sk.create_socket_udp_sniffer()
    if(tuple_headers != None):
        eth_, ipv4_, udp_packet  = tuple_headers
        print(eth_.destination_mac)
        print(int.from_bytes(ipv4_.protocol, byteorder="little"))