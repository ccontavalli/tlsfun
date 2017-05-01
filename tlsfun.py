#!/usr/bin/python

import scapy.all as sp
import scapy.layers.ssl_tls as tls

import collections
import itertools
import array
import sys
import argparse

class Flow(object):
  """Represents a flow of packets in a specific direction."""

  def __init__(self, direction):
    self.direction = direction

    self.total = 0
    self.buffer = array.array('c')
    self.start = None

    self.messages = []

    self.parsed = False

    self.description = ""
    self.ssl_layers = None
    self.ssl_record_size = 0
    self.ssl_ciphertext_size = 0
    self.ssl_ciphers = []
    self.ssl_compression = []
    self.ssl_names = []

  def Parse(self):
    if self.parsed:
      return
      
    self.parsed = True
    # self.ssl_layers = tls.TLSRecord(self.buffer.tostring())
    self.ssl_layers = tls.TLS(self.buffer.tostring())
    self.ExtractSSLData(self.ssl_layers)

    self.description, self.ssl_record_size, self.ssl_ciphertext_size = self.GetSSLDescription()

  def IsHandshake(self):
    self.Parse()
    return tls.TLSHandshake in self.ssl_layers or tls.TLSChangeCipherSpec in self.ssl_layers

  def __str__(self):
    self.Parse()
    total = 0
    output = ""
    for rn, r in self.messages:
      length = len(r[sp.TCP].payload)
      total += length
      output += "\n    [%04d]% 5d /% 6d %s" % (rn, length, total, self.direction)
    output += "\n      buffer: %d - %s" % (len(self.buffer), self.description)
    #print output
    #self.ssl_layers.show()
    return output

  def Add(self, index, packet):
    tcp = packet[sp.TCP]

    if self.start is None:
      self.start = tcp.seq

    offset = tcp.seq - self.start
    length = len(tcp.payload)

    if offset > len(self.buffer):
      self.buffer.extend((offset - len(self.buffer)) * 'E')
    self.buffer[offset:offset + length] = array.array('c', str(tcp.payload))
    self.total += length

    self.messages.append((index, packet))

  def ExtractSSLData(self, packet):
    if tls.TLSServerHello in packet:
      self.ssl_ciphers.append(tls.TLS_CIPHER_SUITES.get(packet[tls.TLSServerHello].cipher_suite, "unknown"))
      self.ssl_compression.append(tls.TLS_COMPRESSION_METHODS.get(packet[tls.TLSServerHello].compression_method, "unknown"))
    if tls.TLSServerName in packet:
      self.ssl_names.append(packet[tls.TLSServerName].data)

  def GetSSLDescription(self):
    ssl = self.ssl_layers
    result = ""
    last = ""
    recordsize = 0
    ciphersize = 0
    for i in itertools.count():
      layer = ssl.getlayer(i)
      if not layer:
        break
      #if isinstance(layer, tls.TLSExtension):
      #  continue
      #if isinstance(layer, sp.Raw):
      #  continue
      name = str(layer.__class__.__name__)
      if name == last:
        result += "."
        continue
      last = name
      result += "/" + name
      if isinstance(layer, tls.TLSRecord) or isinstance(layer, tls.SSLv2Record):
        if hasattr(layer, "version") and layer.version:
          result += "|%s" % layer.version
        if layer.length is not None:
          result += "[%d]" % layer.length
          recordsize += layer.length
      if isinstance(layer, tls.TLSCiphertext):
        result += "{%d}" % len(layer.data)
        ciphersize += len(layer.data)

    if isinstance(ssl[i - 1], sp.Raw):
      result += "{%d}" % len(ssl[i - 1].load)
    if recordsize:
      result += " (record %d)" % recordsize
    if ciphersize:
      result += " (cipher %d)" % ciphersize
    if tls.TLSServerName in ssl:
      result = "%s=%s" % (ssl[tls.TLSServerName].data, result)

    # size = self.GetTLSSize(packet)
    # result += "{%d}" % size
    return result, recordsize, ciphersize


class Exchange(object):
  """Represents a TLS request and its response."""

  def __init__(self, ctuple):
    self.ctuple = ctuple

    self.requests = Flow("<")
    self.responses = Flow(">")

  def Summary(self):
    self.requests.Parse()
    self.responses.Parse()

    output = ""
    output += "requests tcp:%d r:%d ct:%d " % (self.requests.total, self.requests.ssl_record_size, self.requests.ssl_ciphertext_size)
    output += "responses tcp:%d r:%d ct:%d " % (self.responses.total, self.responses.ssl_record_size, self.responses.ssl_ciphertext_size)
    return output

  def __str__(self):
    self.requests.Parse()
    self.responses.Parse()

    output = "request tcp:%d/r:%d/ct:%d, response tcp:%d/r:%d/ct:%d - names:%s, ciphers:%s, compression:%s" % (
        self.requests.total, self.requests.ssl_record_size, self.requests.ssl_ciphertext_size, self.responses.total, self.responses.ssl_record_size, self.responses.ssl_ciphertext_size,
        self.requests.ssl_names + self.responses.ssl_names, self.requests.ssl_ciphers + self.responses.ssl_ciphers, self.requests.ssl_compression + self.responses.ssl_compression)
    output += "%s" % str(self.requests)
    output += "%s" % str(self.responses)
    return output

  def Add(self, ctuple, index, packet):
    if ctuple == self.ctuple:
      if self.responses.messages:
        return False
      flow = self.requests
    else:
      flow = self.responses
    flow.Add(index, packet)

    return True


class Connection(object):
  """Represents a set of exchanges on a given TCP/IP connection."""

  kACK = 0x10
  kSYN = 0x02

  def __init__(self):
    self._order = None

    self._handshake = []
    self._exchanges = []

    self._exchange = None

  @staticmethod
  def Get5Tuple(packet):
    if sp.IP not in packet:
      return None
    if sp.TCP not in packet:
      return None
    return (packet[sp.IP].src, packet[sp.TCP].sport), (packet[sp.IP].dst, packet[sp.TCP].dport)

  def Summary(self):
    self.DispatchExchange()

    ctuple = None
    if len(self._exchanges) >= 1:
      ctuple = self._exchanges[0].ctuple
    elif len(self._handshake) >= 1:
      ctuple = self._handshake[0].ctuple
    if ctuple is None:
      return ""

    output = "%s - %d" % (str(ctuple), self._order)
    for hsn, hs in enumerate(self._handshake):
      output += "\n  %s" % hs.Summary()
    for hsn, hs in enumerate(self._exchanges):
      output += "\n  %s" % hs.Summary()
    return output

  def __lt__(self, other):
    if self._order != other._order:
      return self._order < other._order
    return id(self) < id(other)

  def __eq__(self, other):
    return self._order == other._order

  def __str__(self):
    self.DispatchExchange()

    ctuple = None
    if len(self._exchanges) >= 1:
      ctuple = self._exchanges[0].ctuple
    elif len(self._handshake) >= 1:
      ctuple = self._handshake[0].ctuple
    if ctuple is None:
      return ""

    output = "%s - %d handshake, %d exchanges" % (ctuple, len(self._handshake), len(self._exchanges))
    for hsn, hs in enumerate(self._handshake):
      output += "\n  handshake[%d]: %s" % (hsn, str(hs))
    for hsn, hs in enumerate(self._exchanges):
      output += "\n  exchange[%d]: %s" % (hsn, str(hs))
    return output

  def DispatchExchange(self):
    if self._exchange is None:
      return
    if self._exchange.requests.IsHandshake() or self._exchange.responses.IsHandshake():
      self._handshake.append(self._exchange)
    else:
      self._exchanges.append(self._exchange)
    self._exchange = None

  def Push(self, index, ctuple, packet):
    if self._order is None:
      self._order = index

    tcp = packet[sp.TCP]
    length = len(tcp.payload)
    # Ignore ack packets with no payload, and syns.
    if length == 0 and tcp.flags & self.kACK:
      return
    if length == 0 and tcp.flags & self.kSYN:
      return

    if self._exchange == None or not self._exchange.Add(ctuple, index, packet):
      self.DispatchExchange()
      self._exchange = Exchange(ctuple)
      self._exchange.Add(ctuple, index, packet)

def main():
  parser = argparse.ArgumentParser(description=
      "Prints details of requests and responses in TLS streams "
      "by reconstructing TCP streams in a pcap file.")
  parser.add_argument("pcap", metavar="FILE.pcap", type=str, nargs=1,
                      help="Name of a pcap file to parse")
  parser.add_argument("--dump", dest="dump", action="store_true", help="Print detailed information about each exchange")
  parser.add_argument("--no-dump", dest="dump", action="store_false")
  parser.add_argument("--summary", dest="summary", action="store_true", help="(default) Print a summary of all exchanges")
  parser.add_argument("--no-summary", dest="summary", action="store_false")
  parser.set_defaults(summary=True)

  args = parser.parse_args()

  connections = collections.defaultdict(Connection)
  packets = sp.rdpcap(args.pcap[0])
  for index, packet in enumerate(packets):
    ctuple = Connection.Get5Tuple(packet)

    # Skip non TCP packets.
    if not ctuple:
      continue

    # Retrieve the connection object.
    key = tuple(sorted(ctuple))
    connection = connections[key]
    connection.Push(index, ctuple, packet)

  if args.dump:
    for connection in sorted(connections.itervalues()):
      data = str(connection)
      if not data:
        continue
      print "%s" % data

  if args.summary:
    for connection in sorted(connections.itervalues()):
      data = connection.Summary()
      if not data:
        continue
      print "%s" % data
      
if __name__ == "__main__":
  main()
