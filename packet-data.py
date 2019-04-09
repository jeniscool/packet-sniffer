
#   - Ethernet header: dst, src, type;
class Ethernet:

    def __init__(self, dst, scr, p_type):
        self.dst = dst
        self.src = src
        self.p_type = p_type

#   - IP header: version, ihl, tos, len, if, flags, frag, ttl, proto, chksum, src, dest;
class IP:

    def __init__(self, v, ihl, tos, len, p_if, flags, frag, ttl, proto, chksum, src, dest):
        self.v = v
        self.ihl = ihl
        self.tos = tos
        self.len = len
        self.p_if = p_if
        self.flags = flags
        self.frag = frag
        self.ttl = ttl
        self.proto = proto
        self.chksum = chksum
        self.src = src
        self.dest = dest

#   - TCP header: sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options;
class TCP:

    def __init__(self, sport, dport, seq, ack, dataofs, reserved, flags, window, chksum, urgptr, options):
        self.sport = sport
        self.dport = dport
        self.seq = seq
        self.ack = ack
        self.dataofs = dataofs
        self.reserved = reserved
        self.flags = flags
        self.window = window
        self.chksum = chksum
        self.urgptr = urgptr
        self.options = options

#   - UDP header: sport, dport, len, chksum;
class UDP:

    def __init__(self, sport, dport, len, chksum):
        self.sport = sport
        self.dport = dport
        self.len = len
        selfchksum = chksum

#   - Occasionally some other protocol might show up, such as ARP, which is a transport layer protocol.