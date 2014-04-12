
import lw, pkt_tools

var num_pkts = 0

let pump = eventpump_new()
let udp = udp_new(pump)

udp.on_data do (udp:LW_UDP; address:LW_Addr; buffer:cstring; size:csize){.cdecl.}:
  echo "Got packet of size ", size, " from ", address


echo "Running client" 
var addy = addr_new_port("localhost",8079)
udp.hostAddr addy

let
  helloPkt = ("HELLO",'\x42')
block:
  var op = initOpkt 10
  op << '\x1b'
  op << helloPkt[0]
  op << helloPkt[1]
  udp.send addy, op

if not udp.hosting:
  echo "What is this??"
  quit 1
echo pump.startEventloop

udp.delete
pump.delete

