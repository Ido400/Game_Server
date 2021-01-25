import logging as log
from sys import byteorder
import threading as thread
from socket_ import ipv4

class udp_header():
    def __init__(self, source_port, destination_port, length, checksum, data):
        self.source_port = source_port.to_bytes(2, byteorder="little")
        self.destination_port = destination_port.to_bytes(2, byteorder="little")
        self.lenght = length.to_bytes(2, byteorder="little")
        self.checksum = checksum.to_bytes(2, byteorder="little")
        self.data = data
    
   
    
    
class udp_server():
    def __init__(self, source_port):
       self.source_port = source_port
    

    def send(self, destination_ip, destination_port, data):
        #this function will send the data into the desire destination
        
        #create a list of udp datagrams
        udp_datagrams = []

        #encapusulation of udp datagrams into ipv4 packets
        ipv4_packet = []
        for i, datagram in enumerate(udp_datagrams):
            ipv4_ = ipv4(4, 5, 3, 17, None, None, destination_ip, datagram, 0, None, 0, i)
            ipv4.set_checksum()
            ipv4_packet.append(ipv4_)
        

        pass
    
    def recvfrom():
        #this function will get the udp packet at a spesific port
        pass

    def create_udp_datagrams(self, data, destination_port):
        #this funtion will create udp datagramss
        pass
        

    def cut_the_data(data_lenght_bits, data):
        #this function will cuut the data untill it can be send 
        # it will return a list of the section from the data  
       pass
            


