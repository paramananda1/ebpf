#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
from bcc import BPF
from ctypes import *
from struct import *
from sys import argv
from datetime import datetime

import sys
import socket
import os
import struct
import binascii
import time

CLEANUP_N_PACKETS  = 50       #run cleanup every CLEANUP_N_PACKETS packets received
MAX_URL_STRING_LEN = 8192     #max url string len (usually 8K)
MAX_AGE_SECONDS    = 30       #max age entry in bpf_sessions map

#convert a bin string into a string of hex char
#helper function to print raw packet in hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)

    return reduce(lambda x,y:x+y, lst)

#print str until CR+LF
def printUntilCRLF(str):
    for k in range (0,len(str)-1):
      if (str[k] == '\n'):
        if (str[k-1] == '\r'):
          print ("")
          return
      print ("%c" % (str[k]), end = "")
    print("")
    return

#cleanup function
def cleanup():
    #get current time in seconds
    current_time = int(time.time())
    #looking for leaf having:
    #timestap  == 0        --> update with current timestamp
    #AGE > MAX_AGE_SECONDS --> delete item
    for key,leaf in bpf_sessions.items():
      try:
        current_leaf = bpf_sessions[key]
        #set timestamp if timestamp == 0
        if (current_leaf.timestamp == 0):
          bpf_sessions[key] = bpf_sessions.Leaf(current_time)
        else:
          #delete older entries
          if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
            del bpf_sessions[key]
      except:
        print("cleanup exception.")
    return

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    print("examples:")
    print("    http-parse              # bind socket to eth0")
    print("    http-parse -i wlan0     # bind socket to wlan0")
    exit()

#arguments
interface="enp2s0"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print ("binding socket to '%s'" % interface)

# initialize BPF - load source code from http-parse-complete.c
bpf = BPF(src_file = "/home/poc-test.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

#get pointer to bpf map of type hash
bpf_sessions = bpf.get_table("sessions")

#packets counter
packet_count = 0

#dictionary containing association <key(ipsrc,ipdst,portsrc,portdst),payload_string>
#if url is not entirely contained in only one packet, save the firt part of it in this local dict
#when I find \r\n in a next pkt, append and print all the url
local_dictionary = {}

while 1:
    for key, value in bpf_sessions.items():
        print(socket.inet_ntoa(struct.pack('!L', key.src_ip)), 
              socket.inet_ntoa(struct.pack('!L', key.dst_ip)), 
              key.src_port, key.dst_port, value.timestamp, 
              value.req_timestamp, value.res_timestamp, value.req_payload, 
              value.res_payload, value.http_code)
        del bpf_sessions[key]
    time.sleep(10)

