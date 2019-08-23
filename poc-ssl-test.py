#!/usr/bin/python
#
# sslsniff  Captures data on read/recv or write/send functions of OpenSSL,
#           For Linux, uses BCC, eBPF.
#
# USAGE: sslsniff.py [-h] [-p PID] [-c COMM] [-o] [-g] [-d]
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
#  https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md

from __future__ import print_function
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./sslsniff              # sniff OpenSSL and GnuTLS functions
    ./sslsniff -p 181       # sniff PID 181 only
    ./sslsniff -c curl      # sniff curl command only
    ./sslsniff --no-openssl # don't show OpenSSL calls
"""
parser = argparse.ArgumentParser(
    description="Sniff SSL data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("-c", "--comm",
                    help="sniff only commands matching string.")
parser.add_argument("-o", "--no-openssl", action="store_false", dest="openssl",
                    help="do not show OpenSSL calls.")
parser.add_argument('-d', '--debug', dest='debug', action='count', default=0,
                    help='debug mode.')
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()



print("ARGS ::: ",args)
if args.debug or args.ebpf:
    if args.ebpf:
        exit()


b = BPF(src_file = "poc-ssl-test.c",debug = 0)

# It looks like SSL_read's arguments aren't available in a return probe so you
# need to stash the buffer address in a map on the function entry and read it
# on its exit (Mark Drayton)
# #include <openssl/ssl.h>
#
# int SSL_read(SSL *ssl, void *buf, int num);
# SSL_read() tries to read num bytes from the specified ssl into the buffer buf.
#
# int SSL_write(SSL *ssl, const void *buf, int num);
# SSL_write() writes num bytes from the buffer buf into the specified ssl connection.



if args.openssl:
    b.attach_uprobe(name="ssl", sym="SSL_write", fn_name="probe_SSL_write", pid=args.pid or -1)
    b.attach_uprobe(name="ssl", sym="SSL_read", fn_name="probe_SSL_read_enter", pid=args.pid or -1)
    b.attach_uretprobe(name="ssl", sym="SSL_read", fn_name="probe_SSL_read_exit", pid=args.pid or -1)

# process event
start = 0
# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
MAX_BUF_SIZE = 464  # Limited by the BPF stack

def print_event_write(cpu, data, size):
    print_event(cpu, data, size, "WRITE/SEND", "perf_SSL_write")


def print_event_read(cpu, data, size):
    print_event(cpu, data, size, "READ/RECV", "perf_SSL_read_enter")

def print_event_read(cpu, data, size):
    print_event(cpu, data, size, "READ/RECV Exit", "perf_SSL_read_exit")

def print_event(cpu, data, size, rw, evt):
    global start
    event = b[evt].event(data)
    
    # Filter events by command
    if args.comm:
        if not args.comm == event.comm:
            return
#    print (data)
#    if evt == "perf_SSL_write":
    if start == 0:
        start = event.timestamp_ns

    #data = event.v0.decode('utf-8', 'ignore')
    data = event.v0.decode('ascii','ignore')
    # header
    print("%-12s %-18s %-16s %-6s %-6s" % ("FUNC", "TIME(s)", "COMM", "PID", "LEN"))
    time_s = (float(event.timestamp_ns - start)) / 1000000000
    s_mark = "-" * 5 + " DATA " + "-" * 5
    e_mark = "-" * 5 + " END DATA " + "-" * 5
    truncated_bytes = event.len - MAX_BUF_SIZE
    if truncated_bytes > 0:
        e_mark = "-" * 5 + " END DATA (TRUNCATED, " + str(truncated_bytes) + \
                " bytes lost) " + "-" * 5
    fmt = "%-12s %-18.9f %-16s %-6d %-6d\n%s\n%s\n%s\n\n"
    print(fmt % (rw, time_s, event.comm.decode('utf-8', 'replace'),
                 event.pid, event.len, s_mark,
                 data, e_mark))


b["perf_SSL_write"].open_perf_buffer(print_event_write)
b["perf_SSL_read_enter"].open_perf_buffer(print_event_read)
b["perf_SSL_read_exit"].open_perf_buffer(print_event_read)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

