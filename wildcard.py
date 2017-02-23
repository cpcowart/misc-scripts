#!/usr/bin/env python

# This script provides a way to unroll discontiguous wildcard masks
# into a list of addresses or subnets (with normalized netmasks).

import socket, struct, ipaddress

def mask_from_slash(slash):
    """
    Generates an integear bitwise netmask from a prefix length argument
    """
    mask = 0x00000000
    for bit in range(0, slash):
        mask = (mask >> 1) | 0x80000000
    return mask

def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]

def is_bit_on(number, bit):
    """
    Returns true if the nth position bit (prefix length style) is on
    in number
    """
    return (number & (1 << (32 - bit))) != 0

def contiguous_bits(mask):
    """
    Return an array of range tuples (start, end) of groups of on bits in
    the discontiguous mask
    """
    ranges = []
    start, end = (None, None)
    for bit in range(1,33):
        if is_bit_on(mask, bit):
            if start:
                end = bit
            else:
                start = bit
                end = bit
        elif end:
            ranges.append((start, end))
            start, end = (None, None)
    if end:
        ranges.append((start, end))
    return ranges

def unroller(ranges, prefixes):
    """
    Takes an array of prefixes and array of ranges, operates on the
    first range and recurses until returning the full array of unrolled
    prefixes
    """
    if not ranges:
        return prefixes
    unrolled = []
    rng = ranges.pop(0)
    start, end = rng
    bits = end - start + 1
    for prefix in prefixes:
        for field in range(0, 2**bits):
            mask = mask_from_slash(start - 1) | (mask_from_slash(32) >> end)
            unrolled.append((prefix & mask) | (field << (32 - end)))
    return unroller(ranges, unrolled)
    
def unroll(addr, mask):
    """
    Return an array of ipaddress objects with prefix and normal netmasks 
    unrolled from the wildcard mask
    """

    addr_as_long = ip2long(addr)
    mask_as_long = ip2long(mask)

    # If the final bitstring ends in 32, we will return subnets instead
    # of addresses, so set it aside for later
    rng = None
    ranges = contiguous_bits(mask_as_long)
    if ranges[-1][1] == 32:
        rng = ranges.pop()
    unrolled = unroller(ranges, [addr_as_long])

    processed = []
    for address in unrolled:
        if rng:
            start, end = rng
            network = address & mask_from_slash(start - 1)
            processed.append(ipaddress.IPv4Network((network, start - 1)))
        else:
            processed.append(ipaddress.IPv4Network(address))

    return processed

addr = "10.12.14.16"

# 0x00010001
mask = "0.1.0.1"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# 0x00010000
mask = "0.1.0.0"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# 0x00018001
mask = "0.1.128.1"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# 0x00018000
mask = "0.1.128.0"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# 0x00FF0081
mask = "0.255.0.129"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: ... and that's a lot" % len(output)

# 0xF0000002
mask = "240.0.0.2"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# 0x00F00003
mask = "0.240.0.3"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks: %s" % (len(output), output)

# [{'10.0.1.64': '255.0.7.224'}

addr = "10.0.1.64"
mask = "255.0.7.224"
print "Unrolling %s/%s" % (addr, mask)
output = unroll(addr, mask)
print "Results in %d networks, which is a lot" % len(output)
