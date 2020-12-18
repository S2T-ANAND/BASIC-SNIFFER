import os
import socket
import struct
import ctypes
import time
# host to listen
# the computer on which terminal is running
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
IPAddr = s.gecktsoname()[0]
s.close()
def sniffing() : 
    while True : 
        sniffer = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer.bind(('wlp7s0', 0))
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = raw_buffer[0 : 14]
            ip1_header = raw_buffer[14 : 34]
            ip2_header = raw_buffer[34 : 38]

            # DLL section
            dest, src, prot = struct.unpack('!6s 6s H' , ip_header) 
            dest_mac = get_mac(dest)
            src_mac = get_mac(src)
            proto = socket.htons(prot)

            # ip section
            storeobj = struct.unpack("!BBHHHBBH4s4s", ip1_header)
            VERSION = storeobj[0] >> 4  
            TOTAL_LENGTH = storeobj[2]
            PROTOCOL = storeobj[6]
            SOURCE_ADDRESS = socket.inet_ntoa(storeobj[8])
            DESINATION_ADDRESS = socket.inet_ntoa(storeobj[9])
            internet_layer = {'Version' : VERSION,
            "Total Length" : TOTAL_LENGTH,
            "Source Address" : SOURCE_ADDRESS,
            "Destination Address" : DESINATION_ADDRESS}

            # transport
            storeobj1 = struct.unpack('!HH',ip2_header)
            SOURCE_PORT = storeobj1[0] 
            DESTINATION_PORT = storeobj1[1]
            network_layer = {"Source Port" : SOURCE_PORT,
            "Destination Port" : DESTINATION_PORT
            }

            print("--------------------------------------------------------------------------------------------------------------")
            print("--------------------------------------------------------------------------------------------------------------")
            if IPAddr == DESINATION_ADDRESS :
            	print('The packet is INCOMING')
            else :
            	print('The packet is OUTGOING  \n')
            print('___________DATA LINK LAYER___________')
            print('Destination :  {}, Source :  {}. Protocol :  {}'.format(dest_mac, src_mac, proto)) 
            print('\n')
            print('___________INTERNET LAYER___________')
            print('Packet is using protocol ' + get_protocol(PROTOCOL))
            print(internet_layer)
            print('\n')  
            print('___________NETWORK LAYER___________')
            print(network_layer)
            print('\n')
            time.sleep(2) # for readable transition
            
def get_mac(addr): 
    bytes_str = map('{:02x}'.format,addr)
    return ':'.join(bytes_str).upper()

def get_protocol(n):
	if n == 1 :
		return 'ICMP'
	elif n == 2 :
		return 'IGMP'
	elif n == 3 :
		return 'GGP'
	elif n == 4 :
		return 'IP ENCAPSULATION'
	elif n == 6 :
		return 'TCP'
	elif n == 11 :
		return 'NVP'
	elif n == 17 :
	  	return 'UDP'
	elif n == 18 :
		return 'MUX'
	else :
		return 'LESSER KNOWN'

def main() : 
	# working on Linux
    sniffing()
if __name__ ==  '__main__':
    main()