
import lw, pkt_tools, strutils

let pump = eventpump_new()
let udp = udp_new(pump)

let
  helloPkt = ("HELLO",'\x42')

udp.on_data do (udp:LW_UDP; address:LW_Addr; buffer:cstring; size:csize){.cdecl.}:
  var id: char
  var pkt = buffer.toIpkt(size)
  pkt >> id
  case id
  of '\x1b':
    var helloPacket: type(helloPkt)
    pkt >> helloPacket[0]
    pkt >> helloPacket[1]
    if helloPacket != helloPkt:
      echo "Failed connection attempt from $#:" % $address
      echo helloPacket, " vs ", helloPkt
    else:
      echo "Success connection from $#" % $address
    
  else:
    echo "Unknown packet type '$#' from $#".format(id,address)

echo "Running server"
udp.host 8079

if not udp.hosting:
  echo "What is this??"
  quit 1
echo pump.startEventloop

udp.delete
pump.delete

