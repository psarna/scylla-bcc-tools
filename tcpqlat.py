#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpqlat    Trace TCP active connection latency (connect).
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpqlat [-h] [-t] [-p PID]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 19-Feb-2016   Brendan Gregg   Created this.
# 14-Aug-2020   Piotr Sarna     Hacked queue latency on top.

from bcc import BPF
from socket import inet_ntop
from struct import pack
import argparse
import time

# arg validation
def positive_float(val):
    try:
        ival = float(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a float")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival

# arguments
examples = """examples:
    ./tcpqlat           # trace all TCP latencies
    ./tcpqlat 1         # trace latency slower than 1 ms
    ./tcpqlat 0.1       # trace latency slower than 100 us
    ./tcpqlat -t        # include timestamps
    ./tcpqlat -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects and show connection latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("duration_ms", nargs="?", default=0,
    type=positive_float,
    help="minimum duration to trace (ms)")
parser.add_argument("-v", "--verbose", action="store_true",
    help="print the BPF program for debugging purposes")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

if args.duration_ms:
    # support fractions but round to nearest microsecond
    duration_us = int(args.duration_ms * 1000)
else:
    duration_us = 0   # default is show all

debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>

struct tcp_data_t {
    u32 pid;
    u64 event_ts_ns;
    u64 packet_ts_ns;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(tcp_events);

int trace_leave_queue(struct pt_regs *ctx, const struct sk_buff *skb)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER

    u64 packet_ts_ns = skb->tstamp;
    char buf[sizeof(struct skb_shared_info)];
    bpf_probe_read_kernel(buf, sizeof(struct skb_shared_info), (struct skb_shared_info *)(uintptr_t)skb->end);
    ktime_t hwtstamp = ((struct skb_shared_info *)buf)->hwtstamps.hwtstamp;
    if (hwtstamp) {
        packet_ts_ns = hwtstamp;
    }

#ifdef MIN_LATENCY
    if (packet_ts_ns / 1000 < DURATION_US) {
        return 0; // connect latency is below latency filter minimum
    }
#endif

    struct tcp_data_t data = {.pid = pid};
    data.event_ts_ns = bpf_ktime_get_ns();
    data.packet_ts_ns = packet_ts_ns;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    tcp_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

if duration_us > 0:
    bpf_text = "#define MIN_LATENCY\n" + bpf_text
    bpf_text = bpf_text.replace('DURATION_US', str(duration_us))

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if debug or args.verbose or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="skb_copy_datagram_iter", fn_name="trace_leave_queue")

# process event
start_ts = 0

def print_tcp_event(cpu, data, size):
    event = b["tcp_events"].event(data)
    now = time.time() * 1000;
    now_monotonic = time.monotonic() * 1000;
    event_ts = float(event.event_ts_ns) / 1000000;
    event_overhead = now_monotonic - event_ts;
    packet_ts = float(event.packet_ts_ns) / 1000000;
    packet_latency = max(0, now - packet_ts - event_overhead);
    print("%-10d %-32s %-16.3f %-16.3f" % (event.pid,
        event.task.decode('utf-8', 'replace'), packet_latency, packet_ts))

# header
print("%-10s %-32s %-16s %-32s" % ("PID", "COMM", "LAT(ms)", "TS(ms)"))

# read events
b["tcp_events"].open_perf_buffer(print_tcp_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
