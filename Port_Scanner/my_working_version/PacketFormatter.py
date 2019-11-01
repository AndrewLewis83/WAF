import struct
import socket

class PacketFormatter:

	def ethernet_dissect(self, ethernet_data):
		dest_mac, src_mac, protocol = struct.unpack('!6s6sH',ethernet_data[:14])
		return self.mac_format(dest_mac), self.mac_format(src_mac), socket.htons(protocol), ethernet_data[14:]
	
	def mac_format(self, mac):
		mac = map('%02x'.format, mac)
		return ':'.join(mac).upper()
	
	def ipv4_dissect(self, ip_data):
		ip_protocol, source_ip, target_ip = struct.unpack('!9x B 2x 4s 4s', ip_data[:20])
		return ip_protocol, self.ipv4_format(source_ip), self.ipv4_format(target_ip), ip_data[20:]
	
	def ipv4_format(self, address):
		return '.'.join(map(str, address))

	def tcp_dissect(self, transport_data):
		source_port, dest_port = struct.unpack('!HH', transport_data[:4])
		return source_port, dest_port

	# this is the tcp_dissect method. I could have just called this method again, based on where the source_port and dest_port are.
	def udp_dissect(self, transport_data):
		source_port, dest_port = struct.unpack('!HH', transport_data[:4])
		return source_port, dest_port

	# this returns the type and code from the icmp packet.
	def icmp_dissect(self, transport_data):
		type, code = struct.unpack('!bb', transport_data[:2])
		return type, code
		
	def get_host_ip(self):
		return socket.gethostbyname(socket.gethostname())