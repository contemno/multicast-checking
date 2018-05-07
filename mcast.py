"""Module for checking multicast (destination group & port) for traffic."""

from socket import socket, inet_aton, AF_INET, SOCK_DGRAM, IPPROTO_UDP, SOL_SOCKET, SO_REUSEADDR, \
    IPPROTO_IP, IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP, INADDR_ANY

import struct
import queue
import threading
from time import sleep, perf_counter as timer

#Socket option for returning TTL field value of incoming UDP multicast packets. Sourced from include/linux/in.h
IP_RECVTTL = 12

#Timeout for receiving multicast traffic
MCAST_TIMEOUT = 10

def start_check(mcast_list):
    """Main thread dispatcher to run checks in parallel."""
    results = queue.Queue()
    workqueue = queue.Queue()
    threads = []
    num_worker_threads = 100
    stoprequestedevent = threading.Event()

    for mcast_address in mcast_list:
        workqueue.put(mcast_address)

    while len(threads) < num_worker_threads:
        threads.append(
            threading.Thread(
                target=_worker,
                args=(
                    workqueue,
                    results,
                    stoprequestedevent
                )
            )
        )
        threads[-1].start()

    for _ in range(len(mcast_list)):
        try:
            yield results.get()
        except KeyboardInterrupt:
            stoprequestedevent.set()
            break

def _worker(workqueue, results, stoprequestedevent):
    """Worker function to check queued multicast groups for traffic"""
    while not stoprequestedevent.is_set():
        try:
            results.put(
                check_group(
                    *workqueue.get(False),
                    stoprequestedevent=stoprequestedevent
                )
            )
            workqueue.task_done()
        except KeyboardInterrupt:
            stoprequestedevent.set()
        except queue.Empty:
            break

def check_group(mcast_id, mcast_group, mcast_port, stoprequestedevent):
    """Check multicast group for traffic."""
    feed = {'srclist': [], 'pktcount': 0}
    timed = {'start': timer(), 'end': 0}
    ttl = {'initial': 0, 'final': 0}

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sock.setblocking(False)

    #Set socket option to return TTL cmsg of incoming packets
    sock.setsockopt(IPPROTO_IP, IP_RECVTTL, 1)
    #Build data structure for requesting the kernel to join or leave a multicast shared tree
    mreq = struct.pack("=4sl", inet_aton(mcast_group), INADDR_ANY)
    #Set socket option to join the multicast group
    sock.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq)
    #bind the local port to the multicast group
    sock.bind((mcast_group, mcast_port))

    # Try to collect 100 (maybe more are needed?) packets, because the first couple packets
    # may be tunnelled from the Rendezous Point before the Shortest Path Tree cut-over takes place
    # which doesn't give us the true TTL of a packet traversing the network directly
    # from source to receiver.
    try:
        while feed['pktcount'] < 100 and timer() - timed['start'] < MCAST_TIMEOUT and \
            not stoprequestedevent.is_set():
            try:
                _, ancdata, _, (sourceip, _) = sock.recvmsg(65535, 65535)
            except BlockingIOError:
                sleep(0.1)
            #except KeyboardInterrupt:
            #    raise
            else:
                feed['pktcount'] += 1
                feed['srclist'].append(sourceip)
                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == 0 and cmsg_type == 2:
                        if feed['pktcount'] == 1:
                            timed['end'] = timer()
                            ttl['initial'] = int.from_bytes(cmsg_data, byteorder='little')
                        else:
                            ttl['final'] = int.from_bytes(cmsg_data, byteorder='little')
        return mcast_id, list(set(feed['srclist'])) or ['None'], ttl['initial'], ttl['final'], \
            max(timed['end'] - timed['start'], 0)
    finally:
        sock.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, mreq)
        sock.close()

# Various socket options available:
#define IP_TOS             1	/* int; IP type of service and precedence.  */
#define IP_TTL             2	/* int; IP time to live.  */
#define IP_HDRINCL         3	/* int; Header is included with data.  */
#define IP_OPTIONS         4	/* ip_opts; IP per-packet options.  */
#define IP_ROUTER_ALERT    5	/* bool */
#define IP_RECVOPTS        6	/* bool */
#define IP_RETOPTS         7	/* bool */
#define IP_PKTINFO         8	/* bool */
#define IP_PKTOPTIONS      9
#define IP_PMTUDISC        10	/* obsolete name? */
#define IP_MTU_DISCOVER    10	/* int; see below */
#define IP_RECVERR         11	/* bool */
#define IP_RECVTTL         12	/* bool */
#define IP_RECVTOS         13	/* bool */
#define IP_MULTICAST_IF    32	/* in_addr; set/get IP multicast i/f */
#define IP_MULTICAST_TTL   33	/* u_char; set/get IP multicast ttl */
#define IP_MULTICAST_LOOP  34	/* i_char; set/get IP multicast loopback */
#define IP_ADD_MEMBERSHIP  35	/* ip_mreq; add an IP group membership */
#define IP_DROP_MEMBERSHIP 36	/* ip_mreq; drop an IP group membership */
