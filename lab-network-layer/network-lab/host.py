#!/usr/bin/python3

import argparse
import asyncio
import os
import socket
import sys
import struct
import json


from cougarnet.sim.host import BaseHost
from cougarnet.util import \
        mac_str_to_binary, mac_binary_to_str, \
        ip_str_to_binary, ip_binary_to_str

from forwarding_table import ForwardingTable
from scapy.all import Ether, IP, ARP

# From /usr/include/linux/if_ether.h:
ETH_P_IP = 0x0800 # Internet Protocol packet
ETH_P_ARP = 0x0806 # Address Resolution packet

# From /usr/include/net/if_arp.h:
ARPHRD_ETHER = 1 # Ethernet 10Mbps
ARPOP_REQUEST = 1 # ARP request
ARPOP_REPLY = 2 # ARP reply

# From /usr/include/linux/in.h:
IPPROTO_ICMP = 1 # Internet Control Message Protocol
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

class Host(BaseHost):
    def __init__(self, ip_forward: bool):
        super(Host, self).__init__()

        self._ip_forward = ip_forward
        self._arp_table = {}
        self.pending = []
        self.forwarding_table = ForwardingTable()
        routes = json.loads(os.environ['COUGARNET_ROUTES'])
        
        for prefix, intf, next_hop in routes:
            self.forwarding_table.add_entry(prefix, intf, next_hop)

        for intf in self.physical_interfaces:
            prefix = '%s/%d' % \
                    (self.int_to_info[intf].ipv4_addrs[0],
                            self.int_to_info[intf].ipv4_prefix_len)
            self.forwarding_table.add_entry(prefix, intf, None)


    def _handle_frame(self, frame: bytes, intf: str) -> None:
        eth = Ether(frame)
        if eth.dst == 'ff:ff:ff:ff:ff:ff' or \
                eth.dst == self.int_to_info[intf].mac_addr:

            if eth.type == ETH_P_IP:
                self.handle_ip(bytes(eth.payload), intf)
            elif eth.type == ETH_P_ARP:
                self.handle_arp(bytes(eth.payload), intf)
        else:
            self.not_my_frame(frame, intf)
        

    def handle_ip(self, pkt: bytes, intf: str) -> None:
        ip = IP(pkt)
        all_addrs = []

        for intf1 in self.int_to_info:
            all_addrs += self.int_to_info[intf1].ipv4_addrs
            
            if ip.dst == '255.255.255.255' or ip.dst in all_addrs:
                if ip.proto == IPPROTO_TCP:
                    self.handle_tcp(pkt)
                
                elif ip.proto == IPPROTO_UDP:
                    self.handle_udp(pkt)

            else:
                self.not_my_packet(pkt, intf)


    def handle_udp(self, pkt: bytes) -> None:
        pass

    def handle_tcp(self, pkt: bytes) -> None:
        pass

    def handle_arp(self, pkt: bytes, intf: str) -> None:
        arp = ARP(pkt)
        if arp.op == ARPOP_REQUEST:
            self.handle_arp_request(pkt, intf)
        else: 
            self.handle_arp_response(pkt, intf)


    def handle_arp_response(self, pkt: bytes, intf: str) -> None:
        pkt = ARP(pkt)
        self._arp_table[pkt.psrc] = pkt.hwsrc
        for pkt1, next_hop1, intf1 in self.pending[:]:
            if next_hop1 == pkt.psrc and intf1 == intf:
                eth = Ether(src=self.int_to_info[intf1].mac_addr, dst=self._arp_table[next_hop1], type=ETH_P_IP)
                frame = eth / pkt1
                self.send_frame(bytes(frame), intf1)
                self.pending.remove((pkt1, next_hop1, intf1))

    def handle_arp_request(self, pkt: bytes, intf: str) -> None:
        pkt = ARP(pkt)
        if pkt.pdst == self.int_to_info[intf].ipv4_addrs[0]:
            self._arp_table[pkt.psrc] = pkt.hwsrc
            dst_mac = pkt.hwsrc
            src_mac = self.int_to_info[intf].mac_addr
            next_hop = pkt.psrc
            src_ip = self.int_to_info[intf].ipv4_addrs[0]
            dst_ip = ip_str_to_binary(next_hop)
            payload = self.create_arp_packet(mac_str_to_binary(src_mac), ip_str_to_binary(src_ip),  dst_ip, mac_str_to_binary(dst_mac), ARPOP_REPLY)
            frame = mac_str_to_binary(dst_mac) + mac_str_to_binary(src_mac) + struct.pack('!H', ETH_P_ARP) + payload
            self.send_frame(bytes(frame), intf)
            
	
    def send_packet_on_int(self, pkt: bytes, intf: str, next_hop: str) -> None:
        if next_hop in self._arp_table:
            next_hop_mac = self._arp_table[next_hop]
            intf_mac = self.int_to_info[intf].mac_addr
            frame = mac_str_to_binary(next_hop_mac) + mac_str_to_binary(intf_mac) + struct.pack('!H', ETH_P_IP) + pkt
            self.send_frame(frame, intf)

        else:
            dst_mac = "ff:ff:ff:ff:ff:ff"
            target_mac = "00:00:00:00:00:00"
            src_mac = self.int_to_info[intf].mac_addr
            src_ip = self.int_to_info[intf].ipv4_addrs[0]
            dst_ip = ip_str_to_binary(next_hop)
            payload = self.create_arp_packet(mac_str_to_binary(src_mac), ip_str_to_binary(src_ip), dst_ip, mac_str_to_binary(target_mac), ARPOP_REQUEST)
            frame = b''
            frame = mac_str_to_binary(dst_mac) + mac_str_to_binary(src_mac)
            frame += struct.pack('!H', ETH_P_ARP) + payload
            self.send_frame(frame, intf)
            self.pending.append((pkt, next_hop, intf))

    def create_arp_packet(self, src_mac, src_ip, dst_ip, dst_mac, arpop):

        pkt = b''
        pkt += struct.pack('!H', 0x0001)
        pkt += struct.pack('!H', ETH_P_IP)
        pkt += struct.pack('!B',6)
        pkt += struct.pack('!B', 4)
        pkt += struct.pack('!H', arpop)
        pkt += struct.pack('!6s', src_mac)
        pkt += struct.pack('!4s', src_ip)
        pkt += struct.pack('!6s', dst_mac) 
        pkt += struct.pack('!4s', dst_ip)

        return pkt
         
    def send_packet(self, pkt: bytes) -> None:
        print(f'Attempting to send packet:\n{repr(pkt)}')
        ip = IP(pkt)
        intf, next_hop = self.forwarding_table.get_entry(ip.dst)
        if next_hop is None:
            next_hop = ip.dst
        if intf is None:
            return
        self.send_packet_on_int(pkt, intf, next_hop)



    def forward_packet(self, pkt: bytes) -> None:
        ip = IP(pkt)
        ip.ttl -= 1
        if ip.ttl <= 0:
            return
        self.send_packet(bytes(pkt))

    def not_my_frame(self, frame: bytes, intf: str) -> None:
        pass

    def not_my_packet(self, pkt: bytes, intf: str) -> None:
        if self._ip_forward:
            self.forward_packet(pkt)
        else:
            pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--router', '-r',
            action='store_const', const=True, default=False,
            help='Act as a router by forwarding IP packets')
    args = parser.parse_args(sys.argv[1:])

    with Host(args.router) as host:
        loop = asyncio.get_event_loop()
        try:
            loop.run_forever()
        finally:
            loop.close()

if __name__ == '__main__':
    main()

