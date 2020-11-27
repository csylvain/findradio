#!/usr/bin/python

import socket
import struct
import time

import argparse

class radioSocket:
  radioIP = "" # no address specified: use all enabled network interfaces
  radioDiscoveryPort = 4992
  radioDiscoveryBuff =  612 # (fyi) payload size
  radioData = []

  def __init__(self, sock=None):
    if sock is None:
      # getaddrinfo returns [0: TCP, 1: UDP, 2: RAW] socket info
      sinfo = socket.getaddrinfo("255.255.255.255", None) # request info for broadcast addr
      # socket info is [0: addr_family=AF_INET, 1: socket_type, 2: proto, 3: null_str, 4: (address, port)]
      self.sock = socket.socket(sinfo[1][0], sinfo[1][1], sinfo[1][2]) # udp:family, udp:socktype, udp:proto
      en = struct.pack('@i', 1)
      self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, en)
      self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, en)
      self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, en)
    else:
      self.sock = sock

  def opensock(self, address=radioIP, portnum=radioDiscoveryPort):
    self.sock.bind((address, portnum))

  def getannounce(self, buffersize=radioDiscoveryBuff, datalist=radioData, verbose=0):
    radioAddress = []
    tbegin = time.monotonic()

    while True:
      pkt, address = self.sock.recvfrom(max(1024, buffersize)) # address is [0: ip_address, 1: port]
      if pkt == b'':
        raise RuntimeError("zero length announce packet")
      if not address[0] in radioAddress:
        radioAddress.append(address[0])
        datalist.append((address[0], pkt))
      elif verbose > 1:
        print('duplicate!')
      if (tnow := (time.monotonic() - tbegin)) > 2.0:
        if verbose > 1:
          print('tdelta ', tnow)
        break

    return datalist

def decodeOUI(oui):
  oui &= 0x00ffffff   # only 24 bits
  if oui == 0x001c2d: # add more oui codes with elif .. elif .. else structure
    return '(Flexradio)'
  else:
    return ''

def decodePktType(header):
    pt = (header & 0xf0000000)>>28
    s = '{:2d}: '.format(pt)

    if pt == 0b0000:
        s += 'IF data w/o streamID'
    elif pt == 0b0001:
        s += 'IF data w/ streamID'
    elif pt == 0b0010:
        s += 'Extension data w/o streamID'
    elif pt == 0b0011:
        s += 'Extension data w/ streamID'
    elif pt == 0b0100:
        s += 'IF context'
    elif pt == 0b0101:
        s += 'Extension context'
    else:
        s += 'Reserved for future VRT types'

    return s

def decodeHeader(header):
  spcn = f'  '
  print('{}      pkt type {}'.format(spcn, decodePktType(header)))
  print('{}     /  C (has_classID)'.format(spcn))
  print('{}    |  /  T (has_trailer)'.format(spcn))
  print('{}    | |  /   RR (reserved)'.format(spcn))
  print('{}    | | |   /   TSI (0: no_TS, 1: UTC, 2: GPS, 3: Other)'.format(spcn))
  print('{}    | | |  |   /   TSF (0: no_fracTS, 1: #samp_ctr, 2: RT, 3: freerun_ctr)'.format(spcn))
  print('{}    | | |  |  |   /   pkt ctr [decimal] (modulo 16)'.format(spcn))
  print('{}    | | |  |  |  |   /           pkt size [decimal] (32-bit words)'.format(spcn))
  print('{}    | | |  |  |  |  |           /'.format(spcn))
  print('{}    | | |  |  |  |  |          |\n'.format(spcn))
  print('{} {:04b} {:1b} {:1b} {:02b} {:02b} {:02b} {:2d}      {:05d}'.format(spcn, \
    (header & 0xf0000000)>>28, \
    (header & 0x08000000)>>27, (header & 0x04000000)>>26, \
    (header & 0x03000000)>>24, (header & 0x00c00000)>>22, (header & 0x00300000)>>20, \
    (header & 0x000f0000)>>16, (header & 0x0000ffff)))
  return '\n'

def main():
  argp = argparse.ArgumentParser(description='listen for VITA-49 discovery packets on LAN', \
    prog='findradio', \
    # use RawFormatter to add extra whitespace after Usage text
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=''' \
      ''')

  argp.add_argument('-d', '--debug', type=int, \
    # if arg present but param is missing (allowed by '?') then provide 'const' value 1
    nargs='?', const=1, \
    # if arg itself is missing then attribute will not be in namespace
    default=argparse.SUPPRESS, \
    help='set DEBUG level of %(prog)s (default: 1)')

  args = argp.parse_args()

  if hasattr(args, 'debug') == False: # arg not present - suppressed from dict
    DEBUG = 0
  elif (t := args.debug) != None: # arg present in dict with possible default int value
    DEBUG = t
  
  t = radioSocket()
  t.opensock()
  print('scanning...\n')
  p = t.getannounce(verbose=DEBUG)
  print('There are {} radios on this network.\n'.format(len(p)))

  for v in p:
    address = v[0]
  
    if DEBUG > 2:
      print('  payload len =', len(v[1])) # 612 - len(7*uint32) = 584

    header, stream_id, class_id_h, class_id_l, \
      timestamp_int, timestamp_frac_h, timestamp_frac_l, \
      payload = struct.unpack('!7I{}s'.format(len(v[1])-struct.calcsize('7I')), bytes(v[1]))
    # "!7I" means 7 uint32 with bytes in network order ("i" is int32, '@' would be native byte order).
    # "584s" <-- youknowdis

    if DEBUG > 1:
      print('{} {} {:#x} {:#x} {:#x} {:#x} {} {} {}'.format(v[0], v[1], \
       header, stream_id, class_id_h, class_id_l, \
       timestamp_int, timestamp_frac_h, timestamp_frac_l)) # frac_h and frac_l are apparently always zero
    elif DEBUG > 2:
      print(payload)

    spcn = f' '*18
    print(' > {:15s}  pkt_header {:#010x}\n'.format(address, header))
    print( (decodeHeader(header) if DEBUG else ''), \
      '{} stream_id   {:#06x}\n'.format(spcn, stream_id), \
      '{} manufacturer_oui     {:#08x} {}\n'.format(spcn, (class_id_h & 0x00ffffff), decodeOUI(class_id_h)), \
      '{} information_code   {:#010x}\n'.format(spcn, (class_id_l & 0xffff0000)), \
      '{} packet_code        {:#010x}\n'.format(spcn, (class_id_l & 0xffff)), \
      '{} timestamp  {} {}\n'.format(spcn, time.ctime(timestamp_int), \
        ('({})'.format(timestamp_int) if DEBUG else ''))) # note use of ternary conditional

    pvals = payload.split() # splits on space char delimiter

    spcn = f' '*20
    for v in pvals:
      t = str(v, 'utf-8').split('=')
      print('{}{:28s} {:s}'.format(spcn, t[0], t[1]))

    print('\n')

  print('done.')
  exit(0)

if __name__ == "__main__":
  main()
