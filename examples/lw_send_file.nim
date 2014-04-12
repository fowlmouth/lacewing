
import lw, strutils, os

proc on_get (server: LW_WS; req: LW_WS_Req){.cdecl.}=
  req.set_mimetype "text/plain"
  req.writef "#$1 $2 $3\r\n".format(paramStr(0), compileDate, compileTime)
  req.write_file "lw_send_file.nim"

let
  pump = eventpump_new()
  server = ws_new(pump)
server.on_get on_get
server.host 8080

discard pump.starteventloop

server.delete
pump.delete
