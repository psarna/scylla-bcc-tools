# Scylla bcc tools

If something doesn't work, retry with sudo. (e.g. "cannot import BPF" errors).

## tcpqlat

Measures the time spent in TCP queues (i.e. time difference between the point when the packet was acknowledged by the kernel and the point when it was read by the user), for each packet.
