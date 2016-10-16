#!/usr/bin/python

import socket, os, struct, sys, optparse, re
from ctypes import *
from struct import *
from threading import Thread

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800

op_list = (20, 21, 22, 23, 24, 25)
keywords = ("object:Win32_", "Win32_", "cim_")
prevention_list = ('Win32_share', 12,)

def log():
        pass

def alert():
        pass

def listener(iface):
        try:
                recvsock= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
                sendsock= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                
                recvsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                sendsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sendsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except:
                print("Error Creating Sockect on Interface " + iface )
                sys.exit()
        try:
                recvsock.bind((iface, 0))
        except:
                print("Error Binding Socket to Interface " + iface)
                sys.exit()
        
        while True:
                frame = recvsock.recvfrom(65565)[0]
                packet = frame[14:]
                ip_intro, ip_length, ip_ident, ip_flags, ip_ttl, ip_protocol, ip_checksum, ip_src_ip, ip_dst_ip \
                          = struct.unpack(">2sHHHBBH4s4s", packet[:20])

                if ip_length > 104:
                        tcp = packet[20:]
                        t_s_port, t_d_port, t_seq_num, t_ack_num, t_info, t_flags, t_win, t_checksum, t_u_ptr, \
                                  d_version, d_p_type, d_p_flags, d_d_rep, d_f_len, d_a_len, d_c_id, d_a_hint, d_con_id, d_op_num = \
                                  struct.unpack("<HH4s4ssBHHHHBB4sHH4s4sHH", tcp[0:44])
##                        t_len = struct.unpack(">H", packet[2:4])

                        if d_version == 5 and d_op_num in op_list:
                                regex = re.compile("[^a-zA-Z1-9 _]")
                                strings = re.sub(regex, '', packet[122:-24]).split()
                                if any(map(lambda match: match in strings, prevention_list)):         
                                        print("blocked "),
                                        print(strings)
                                else:
                                        print("sent "),
                                        print(strings)
                                        try:
                                                sendsock.sendto(packet, (socket.inet_ntoa(ip_dst_ip), 0))
                                        except Exception as ex:
                                                print(ex),
                                                print(" " + socket.inet_ntoa(ip_src_ip) + " -> " + socket.inet_ntoa(ip_dst_ip))

                        else:
                                try:
                                        sendsock.sendto(packet, (socket.inet_ntoa(ip_dst_ip), 0))
                                except Exception as ex:
                                        print(ex),
                                        print(" " + socket.inet_ntoa(ip_src_ip) + " -> " + socket.inet_ntoa(ip_dst_ip))
                else:
                        try:
                                sendsock.sendto(packet, (socket.inet_ntoa(ip_dst_ip), 0))
                        except Exception as ex:
                                print(ex),
                                print(" " + socket.inet_ntoa(ip_src_ip) + " -> " + socket.inet_ntoa(ip_dst_ip))
def main():
        parser = optparse.OptionParser("usage %prog -i [interfaces] -A <Admin IP>")
        parser.add_option("-i", dest="ifs", type="string", help="specify interfaces")
        parser.add_option("-A", dest="admin", type="string", help="specify administrator\'s IP")
        (options, args) = parser.parse_args()
        ifaces = options.ifs
        admin = options.admin
        if (ifaces != None):
                ifaces = ifaces.strip().split(',')
                if (len(ifaces) >= 2):
                        print("[+] starting wmi firewall")
                        for iface in ifaces:
                                t = Thread(target=listener, args=(iface,))
                                t.start()
                else:
                        print("usage %prog -i [interfaces] -A <Admin IP>")
                        print("minimum number of interfaces are 2")
        else:
                print("usage %prog -i [interfaces] -A <Admin IP>")
                print("list of interfaces required")

if __name__ == '__main__':
#exception handling
        try:
                main()
        except KeyboardInterrupt:
                print ('[-] exiting wmi firewall')
                sys.exit()
