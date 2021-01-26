import logging as log
import struct
from sys import byteorder
import threading as thread
from socket_ import ethernet_frame, ipv4, socketSever
import struct 

class udp_header():
    def __init__(self, source_port, destination_port, length, checksum, data):
        self.source_port = source_port.to_bytes(2, byteorder="little")
        self.destination_port = destination_port.to_bytes(2, byteorder="little")
        self.lenght = length.to_bytes(2, byteorder="little")
        self.checksum = checksum.to_bytes(2, byteorder="little")
        self.data = data
        self.udp_datagrams = self.source_port + self.destination_port + \
            self.lenght + self.checksum + self.data
    
     
class udp_server():
    def __init__(self, source_port):
       self.source_port = source_port
    

    def send(self, destination_ip, destination_port, data, destination_mac):
        #this function will send the data into the desire destination
        
        #create a list of udp datagrams
        udp_datagrams = self.create_udp_datagrams(data, destination_port)
        #create ipv4 packet
        ipv4_packets =  ipv4.encapsultion_udp_datagram(udp_datagrams, destination_ip)
       
        #send the ipv4 packets
        ipv4.send_packets(ipv4_packets, destination_mac)

    def recvfrom(self):
        #this function will get the udp packet in spesific port
        sk = socketSever(self.source_port)
        tuple_header = sk.create_socket_udp_sniffer() 
        if(tuple_header != None):
            ethernet_frame_ , ipv4_ , udp_packet = tuple_header
            tuple_udp = self.descapsulation_udp_datagram(udp_packet)
            if(tuple_udp != None):
                data, destination_port = tuple_udp
                return data, destination_port, ipv4_.destination_ip, ethernet_frame_.source_mac
            
        
    
    def descapsulation_udp_datagram(self, udp_packet):
        #get the udp header
        source_port, destination_port, len_, checksum = struct.unpack('hhhh' , udp_packet[:20]) 
        data = udp_packet[8:]
        
        #check the destination port equal to the source port
        if(self.source_port == destination_port):
            return data, source_port
        
        return None
        

    def create_udp_datagrams(self, data, destination_port):
        #this funtion will create udp datagramss
        data_bytes = bytes(data)
        len_flag = len(data_bytes) / 8
        len_cut = len_flag
        count = 0
        udp_datagrams = []

        while count != len_flag:
            count += 1
            data_cut = data_bytes[8:]
            udp = udp_header(self.source_port, destination_port, 28, 0, data_bytes[:len_cut -8])
            len_cut = len(data_cut) / 8
            udp_datagrams.append(udp)
        return udp_datagrams
        



udp = udp_server(1234)
while True:
    tuple_data = udp.recvfrom()
    if(tuple_data != None):
        data, dest_port, dest_ip, mac_source = tuple_data
        print(hex(data))