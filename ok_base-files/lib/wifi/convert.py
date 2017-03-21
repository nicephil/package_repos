#!/usr/bin/env python

import sys

fw_size = 2116


def cal_checksum(fdata):
    i = 0
    sum_all = 0
    while i < fw_size - 1:
        sum_all ^= (fdata[i+1] << 8 | fdata[i])
        i += 2
    return sum_all

if __name__ == '__main__':
    # 1. argument parse
    if len(sys.argv) != 2 or (len(sys.argv) == 2 and len(sys.argv[1]) != 17):
        print "convert.py <mac>"
        print "example: conver.py 00:11:22:33:44:55"
        sys.exit(-1)
    newmac = sys.argv[1].split(':')
    # 2. read bin to memory
    f = open('wifi1.caldata', 'rb')
    fdata = bytearray(f.read(fw_size))
    fsize = f.tell()
    if fsize != fw_size:
        print "read bin file failure: " + str(fsize)
        sys.exit(-3)
    f.close()
    # 3. change mac and calculate new checksum
    origin_checksum = (fdata[3] << 8 | fdata[2])
    # add into new mac
    fdata[6] = int(newmac[0], base=16)
    fdata[7] = int(newmac[1], base=16)
    fdata[8] = int(newmac[2], base=16)
    fdata[9] = int(newmac[3], base=16)
    fdata[10] = int(newmac[4], base=16)
    fdata[11] = int(newmac[5], base=16)
    sum_all = cal_checksum(fdata)
    print "sum_all:" + hex(sum_all)
    new_checksum = sum_all ^ origin_checksum ^ 0xFFFF
    print "new checksum: " + hex(new_checksum)
    # 4. write new data to file
    fdata[3] = new_checksum >> 8
    fdata[2] = new_checksum & 0xFF
    # 5. verify
    sum_all = cal_checksum(fdata)
    if sum_all != 0xFFFF:
        print "change failure!"
        sys.exit(-2)
    # 6. write into bin
    f2 = open('wifi1.caldata', 'wb+')
    print "fdata.len: " + str(len(fdata))
    f2.write(fdata)
    f2.close()
