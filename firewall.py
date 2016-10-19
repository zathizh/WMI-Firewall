#!/usr/bin/python

import socket, os, struct, sys, optparse, re, time
from ctypes import *
from struct import *
from threading import Thread

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800

op_list = {20:"ExecQuery", 21:"ExecQueryAsync", 22:"ExecNotificationQuery", 23:"ExecNotificationQueryAsync", 24:"ExecMethod", 25:"ExecMethodAsync"}

keywords = ("object:Win32_", "Win32_", "cim_")
prevention_list = ('Win32_share',)

#log file
fp = open('/var/log/wmifirewall.log', 'a+')

def log(l_time, status, ip_src_ip, ip_dst_ip, t_s_port, t_d_port, d_op_num, d_meth, d_command, r_data):
        fp.write(l_time),
        fp.write(","),
        fp.write(status),
        fp.write(","),
        fp.write(ip_src_ip),
        fp.write(","),
        fp.write(ip_dst_ip),
        fp.write(","),
        fp.write(str(t_s_port)),
        fp.write(","),
        fp.write(str(t_d_port)),
        fp.write(","),
        fp.write(str(d_op_num)),
        fp.write(","),
        fp.write(d_meth),
        fp.write(","),
        fp.write(d_command),
        fp.write(","),
        fp.write(r_data),
        fp.write("\n")

def alert(t, status, ip_src_ip, ip_dst_ip, t_d_port, msg):
        print(t),
        print("  "),
        print(status),
        print("  "),
        print(ip_src_ip),
        print(" -> "),
        print(ip_dst_ip),
        print(" : "),
        print(t_d_port),
        print(" > "),
        print(msg)
        
def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)

    s = ~s & 0xffff
    return s

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
                        t_s_port, t_d_port, t_seq_num, t_ack_num, t_info, t_flags, t_win, t_checksum, t_u_ptr = \
                                  struct.unpack(">HHLLsBHHH", tcp[0:20])
                        d_version, d_p_type, d_p_flags, d_d_rep, d_f_len, d_a_len, d_c_id, d_a_hint, d_con_id, d_op_num = \
                                  struct.unpack("<HBB4sHH4s4sHH", tcp[20:44])

                        if d_version == 5 and d_op_num in op_list.keys():
                                regex = re.compile("[^a-zA-Z1-9 _]")
                                strings = re.sub(regex, '', packet[122:-24]).split()
                                if any(map(lambda x: x in strings, prevention_list)):
                                        match = prevention_list[map(lambda match: match in strings, prevention_list).index(True)]
                                        b_ip_intro = ip_intro
                                        b_ip_length = 40
                                        b_ip_indent = 65001
                                        b_ip_flags = ip_flags
                                        b_ip_ttl = 64
                                        b_ip_protocol = ip_protocol
                                        b_ip_checksum = 0
                                        b_ip_src_ip = ip_dst_ip
                                        b_ip_dst_ip = ip_src_ip

                                        b_t_s_port = t_d_port
                                        b_d_d_port = t_s_port
                                        b_t_seq_num = t_ack_num 
                                        b_t_ack_num = ip_length + t_seq_num - 40
                                        b_t_offset = 5
                                        b_t_reserved = 0

                                        b_t_info = (b_t_offset << 4) + (b_t_reserved)
                                        
                                        b_t_f_urg = 0
                                        b_t_f_ack = 1
                                        b_t_f_psh = 0
                                        b_t_f_rst = 1
                                        b_t_f_syn = 0
                                        b_t_f_fin = 0

                                        b_t_flags = (b_t_f_fin) + (b_t_f_syn << 1) + (b_t_f_rst << 2) + (b_t_f_psh << 3) + \
                                                    (b_t_f_ack << 4) + (b_t_f_urg << 5)
                                        
                                        b_t_win = t_win
                                        b_t_checksum = 0
                                        b_t_u_ptr = 0

                                        ip_header = struct.pack("!2sHHHBBH4s4s",
                                                                b_ip_intro,
                                                                b_ip_length,
                                                                b_ip_indent,
                                                                b_ip_flags,
                                                                b_ip_ttl,
                                                                b_ip_protocol,
                                                                b_ip_checksum,
                                                                b_ip_src_ip,
                                                                b_ip_dst_ip
                                                                )
                                        
                                        b_ip_checksum = checksum(ip_header)

                                        ip_header = struct.pack("!2sHHHBBH4s4s",
                                                                b_ip_intro,
                                                                b_ip_length,
                                                                b_ip_indent,
                                                                b_ip_flags,
                                                                b_ip_ttl,
                                                                b_ip_protocol,
                                                                socket.htons(b_ip_checksum),
                                                                b_ip_src_ip,
                                                                b_ip_dst_ip
                                                                )

                                        tcp_header = struct.pack("!HHLLBBHHH",
                                                                 b_t_s_port,
                                                                 b_d_d_port,
                                                                 b_t_seq_num,
                                                                 b_t_ack_num,
                                                                 b_t_info,
                                                                 b_t_flags,
                                                                 b_t_win,
                                                                 b_t_checksum,
                                                                 b_t_u_ptr
                                                                 )
                                        psh = struct.pack("!4s4sBBH",
                                                          b_ip_src_ip,
                                                          b_ip_dst_ip,
                                                          0,
                                                          b_ip_protocol,
                                                          20,
                                                          )
                                        
                                        psh = psh + tcp_header
                                        
                                        b_t_checksum = checksum(psh)

                                        tcp_header = struct.pack("!HHLLBBH",
                                                                 b_t_s_port,
                                                                 b_d_d_port,
                                                                 b_t_seq_num,
                                                                 b_t_ack_num,
                                                                 b_t_info,
                                                                 b_t_flags,
                                                                 b_t_win,
                                                                 )
                                        tcp_header = tcp_header + struct.pack('H', b_t_checksum) + struct.pack('!H', b_t_u_ptr)
                                        
                                        d_packet = ip_header + tcp_header
                                        
                                        try:
                                                sendsock.sendto(d_packet, (socket.inet_ntoa(b_ip_dst_ip), 0))
                                        except Exception as ex:
                                                print(ex),
                                                print(" " + socket.inet_ntoa(b_ip_src_ip) + " -> " + socket.inet_ntoa(b_ip_dst_ip))

                                        t = time.asctime(time.localtime())
                                        
                                        status = "Blocked "
                                        log(t,
                                            status,
                                            socket.inet_ntoa(ip_src_ip),
                                            socket.inet_ntoa(ip_dst_ip),
                                            t_s_port,
                                            t_d_port,
                                            d_op_num,
                                            op_list[d_op_num],
                                            match,
                                            packet
                                            )

                                        alert(t, status, socket.inet_ntoa(ip_src_ip), socket.inet_ntoa(ip_dst_ip), t_d_port, match)
                                        
                                else:
                                        try:
                                                sendsock.sendto(packet, (socket.inet_ntoa(ip_dst_ip), 0))
                                                
                                                t = time.asctime(time.localtime())
                                                status = "Executed"

                                                match = ""
                                                for keyword in keywords:
                                                        found = map(lambda x: x.find(keyword), strings)
                                                        if 0 in found:
                                                                match = strings[found.index(0)]
                                                                break
                                                        
                                                log(t,
                                                    status,
                                                    socket.inet_ntoa(ip_src_ip),
                                                    socket.inet_ntoa(ip_dst_ip),
                                                    t_s_port,
                                                    t_d_port,
                                                    d_op_num,
                                                    op_list[d_op_num],
                                                    match,
                                                    packet
                                                    )
                                                
                                                alert(t, status, socket.inet_ntoa(ip_src_ip), socket.inet_ntoa(ip_dst_ip), t_d_port, match)
                                                
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
        parser = optparse.OptionParser("usage %prog -i [interfaces]")
        parser.add_option("-i", dest="ifs", type="string", help="specify interfaces")
        (options, args) = parser.parse_args()
        ifaces = options.ifs
        if (ifaces != None):
                ifaces = ifaces.strip().split(',')
                if (len(ifaces) >= 2):
                        print("[+] Starting WMI FIREWALL")
                        try:
                                for iface in ifaces:
                                        t = Thread(target=listener, args=(iface,))
                                        t.daemon = True
                                        t.start()
                                        print("[+] Staring Thread on " + iface)
                                
                                while True:
                                        pass
                        except KeyboardInterrupt:
                                print("")
                                print("[-] Closing Threads")
                                print("[-] Exiting WMI FIREWALL")
                                fp.close()
                                sys.exit()
                else:
                        print("usage %prog -i [interfaces]")
                        print("minimum number of interfaces are 2")
        else:
                print("usage %prog -i [interfaces]")
                print("list of interfaces required")

if __name__ == '__main__':
        main()
