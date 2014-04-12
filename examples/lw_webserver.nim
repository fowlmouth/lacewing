import lw, strutils

let pump = eventpump_new()
let webserver = ws_new(pump)

webserver.on_get do (W: LW_WS; req: LW_WS_Req){.cdecl.}:
  #req.writef "Hello world from %s", lw.version()
  echo req.url
  echo "  ", req.hostname
  echo "  ", req.address
  req.writef "Hello world from $1.<br/>You are $2.".format(
    lw.version(), req.hostname
  )

webserver.host 8080

echo pump.startEventloop

webserver.delete
pump.delete