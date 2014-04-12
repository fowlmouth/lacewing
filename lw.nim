# wrapper for lacewing ( https://github.com/udp/lacewing )
# targetting 0.5.4
# lacewing is BSD licensed. this wrapper is MIT licensed.

when defined(Linux):
  const LibName* = "liblacewing.so"
else:
  {.error: "Your OS is not accounted for in lw.nim".}

type
  LW_addr* = ptr object
  LW_pump* = ptr object
  LW_pumpWatch* = ptr object
  LW_ws* = ptr object
  LW_WS_Upload* = ptr object
  LW_WS_UploadHdr* = ptr object
  LW_WS_Session* = ptr object
  LW_WS_SessionItem* = ptr object
  
  Lacewing* = object
  LW_Timer* = ptr[Lacewing, object]
  
  LW_Filter* = ptr object
  LW_UDP* = ptr object
  LW_Stream* = ptr object
  LW_WS_Req* = LW_Stream
  LW_FDstream* = LW_Stream
  LW_File* = LW_Stream
  LW_Client* = LW_Stream
  LW_ServerClient* = LW_Stream
  
  LW_error* = ptr object
  
  TGetHook* = proc(webserver: LW_ws; req: LW_ws_req) {.cdecl.}
  TTickFunc* = proc (pump: LW_Pump) {.cdecl.}
  TErrorHook* = proc(ws:LW_WS; error:LW_Error){.cdecl.}
  
  TUploadStartHook* = proc(W:LW_WS; req:LW_WS_Req; upload:LW_WS_Upload): void {.cdecl.}
  TUploadChunkHook* = proc(W:LW_WS; req:LW_WS_Req; upload:LW_WS_Upload; buffer:cstring; size:csize) {.cdecl.}
  TUploadDoneHook* = proc(W:LW_WS; req:LW_WS_Req; upload:LW_WS_Upload) {.cdecl.}
  TUploadPostHook* = proc(W:LW_WS; req:LW_WS_Req; uploads:ptr array[50_000, LW_WS_Upload], numUploads:csize) {.cdecl.}

  TTimerHookTick = proc(timer:LW_Timer){.cdecl.}
type 
 streamdef* = object
  sink_data*: proc(stream:lw_stream; buffer:cstring; size:csize):csize{.cdecl.}
  sink_stream*:proc(stream,source:lw_stream; size:csize):csize {.cdecl.}
  retry*: proc(stream:lw_stream; `when`:cint){.cdecl.}
  is_transparent*: proc(stream:lw_stream):bool{.cdecl.}
  close*:proc(stream:lw_stream;immediate:bool):bool{.cdecl.}
  bytes_left*: proc (stream:lw_stream):csize{.cdecl.}
  read*: proc(stream:lw_stream; bytes:csize){.cdecl.}
  cleanup*: proc(stream:lw_stream){.cdecl.}
  tail_size*: csize

{.push callconv: cdecl, dynlib: libname.}

import macros
macro niceString (importName:expr; arg:expr; procName: expr): stmt {.immediate.}=
  echo repr (importName)
  if arg.kind == nnkIdent and arg.ident == !"void":
    result = 
     quote do:
      proc `procName`* : string =  
        proc private : cstring {.importc: `importName`.}
        let x = private()
        let s = $x
        dealloc x
        s
  else:
    result = quote do:
      proc `procName`* (obj: `arg`):string =
        proc private (x: `arg`): cstring {.importc:`importName`.}
        let x = private(obj)
        let s = $x
        dealloc x
        s
  
  echo repr (result)
  
niceString "lw_version", void, version

#proc version_private : cstring {.importc:"lw_version".}

{.push importc:"lw_$1".}

{.push importc:"lw_error_$1".}
proc tostring* (e:LWerror):cstring 
{.pop.}

proc eventpump_new* : LW_pump
{.push importc:"lw_eventpump_$1".}
proc tick* (P:LW_pump): LW_Error
proc start_eventloop*(P:LW_Pump): LW_Error
proc start_sleepy_ticking*(P:LW_Pump; onTickNeeded: TTickFunc  ): LW_Error
# void (* on_tick_needed) (lw_eventpump));
proc post_eventloop_exit* (P:LW_Pump): void
{.pop.}

{.push importc:"lw_pump_$1".}
proc delete* (P:LW_Pump)
proc add_user*(P:LW_Pump)
proc remove_user*(P:LW_Pump)
proc in_use*(P:LW_Pump): bool
proc remove*(P:LW_Pump, w:LW_PumpWatch)
proc post*(P:LW_Pump, fn, param: pointer)
proc tag*(P:LW_Pump): pointer
proc set_tag*(P:LW_Pump; tag:pointer)
{.pop.}

proc timer_new* (P:LW_Pump): LW_Timer
{.push importc:"lw_timer_$1".}
proc delete* (timer:LW_Timer)
proc start* (timer:LW_Timer; milliseconds:clong)
proc started* (timer:LW_Timer): bool
proc stop* (timer:LW_Timer)
proc force_tick* (timer:LW_Timer)
proc tag* (timer:LW_Timer):pointer
proc set_tag* (timer:LW_Timer; tag:pointer)

proc on_tick* (timer:LW_Timer; hook: TTimerHookTick)
{.pop.}

# webserver
proc ws_new* (P:LWPump): LW_ws
{.push importc:"lw_ws_$1".}
proc delete* (ws:LW_WS)
proc host* (ws:LW_WS; port:clong)
proc host_secure*(ws:LW_WS; port:clong)
proc host_filter*(ws:LW_WS; filter:LW_Filter)
proc host_secure_filter*(ws:LW_WS; filter:LW_Filter)
proc unhost* (ws:lw_ws)
proc unhost_secure*(ws:lw_ws)
proc hosting*(ws:lw_ws):bool
proc hosting_secure*(ws:lw_ws):bool
proc port* (ws:lw_ws):clong
proc port_secure*(ws:lw_ws):clong
proc load_cert_file*(ws:lw_ws; filename,passphrase:cstring): bool
proc load_sys_cert*(ws:lw_ws; store_name,common_name,location:cstring):bool
proc cert_loaded* (ws:lw_ws):bool 
proc session_close*(ws:lw_ws; id:cstring)
proc enable_manual_finish*(ws:lw_ws)
proc idle_timeout*(ws:lw_ws):clong
proc set_idle_timeout*(ws:lw_ws; seconds:clong)
proc tag* (ws:lw_ws):pointer
proc set_tag*(ws:lw_ws; tag:pointer)

discard """

/* Webserver */
  lw_import               void* lw_ws_tag                    (lw_ws);
  lw_import               void  lw_ws_set_tag                (lw_ws, void * tag);

  lw_import         const char* lw_ws_upload_form_el_name    (lw_ws_upload);
  lw_import         const char* lw_ws_upload_filename        (lw_ws_upload);
  lw_import         const char* lw_ws_upload_header          (lw_ws_upload, const char * name);
  lw_import               void  lw_ws_upload_set_autosave    (lw_ws_upload);
  lw_import         const char* lw_ws_upload_autosave_fname  (lw_ws_upload);
  lw_import   lw_ws_upload_hdr  lw_ws_upload_hdr_first       (lw_ws_upload);
  lw_import         const char* lw_ws_upload_hdr_name        (lw_ws_upload_hdr);
  lw_import         const char* lw_ws_upload_hdr_value       (lw_ws_upload_hdr);
  lw_import   lw_ws_upload_hdr  lw_ws_upload_hdr_next        (lw_ws_upload_hdr);

"""

proc on_get* (ws:LW_ws, hook: TGetHook): void
proc on_post*(ws:LW_ws; hook: TGetHook): void
proc on_head*(ws:LW_WS; hook: TGetHook): void
proc on_error*(ws:LW_WS; hook: TErrorHook):void
proc on_disconnect*(ws:LW_WS; hook:TGetHook):void

proc on_upload_start* (ws:LW_WS; hook:TUploadStartHook):void
proc on_upload_chunk* (ws:LW_WS; hook:TUploadChunkHook):void
proc on_upload_done* (ws:LW_WS; hook:TUploadDoneHook):void
proc on_upload_post* (ws:LW_WS; hook:TUploadPostHook):void


{.pop.}
{.push importc:"lw_ws_req_$1".}
#proc address* (R:LW_WS_REQ): LW_ADDR {.importc:"lw_ws_req_addr".}
proc secure* (R:LW_WS_REQ): bool
proc url* (R: LW_WS_REQ): cstring
proc hostname*(R:LW_WS_REQ):cstring
proc disconnect*(R:LW_WS_Req)
proc set_redirect*(R:LW_WS_Req; url:cstring)
discard """

  lw_import            lw_addr  lw_ws_req_addr               (lw_ws_req);
  lw_import            lw_bool  lw_ws_req_secure             (lw_ws_req);
  lw_import         const char* lw_ws_req_url                (lw_ws_req);
  lw_import         const char* lw_ws_req_hostname           (lw_ws_req);
  lw_import               void  lw_ws_req_disconnect         (lw_ws_req); 
  lw_import     void  lw_ws_req_set_redirect       (lw_ws_req, const char * url);
"""

proc status* (r:lw_ws_req; code:clong; message:cstring)
proc set_mimetype* (r:lw_ws_req; mimetype:cstring)
proc set_mimetype_ex* (r:lw_ws_req; mimetype:cstring; charset:cstring)
proc guess_mimetype* (r: lw_ws_req; filename:cstring)

discard """
  lw_import   void  lw_ws_req_guess_mimetype     (lw_ws_req, const char * filename);
  lw_import               void  lw_ws_req_finish             (lw_ws_req);
  lw_import             lw_i64  lw_ws_req_last_modified      (lw_ws_req);
  lw_import               void  lw_ws_req_set_last_modified  (lw_ws_req, lw_i64);
  lw_import               void  lw_ws_req_set_unmodified     (lw_ws_req);
  lw_import   void  lw_ws_req_set_header         (lw_ws_req, const char * name, const char * value);
  lw_import               void  lw_ws_req_add_header         (lw_ws_req, const char * name, const char * value);
  lw_import         const char* lw_ws_req_header             (lw_ws_req, const char * name);
  lw_import      lw_ws_req_hdr  lw_ws_req_hdr_first          (lw_ws_req);
  lw_import         const char* lw_ws_req_hdr_name           (lw_ws_req_hdr);
  lw_import         const char* lw_ws_req_hdr_value          (lw_ws_req_hdr);
  lw_import      lw_ws_req_hdr  lw_ws_req_hdr_next           (lw_ws_req_hdr);
  lw_import    lw_ws_req_param  lw_ws_req_GET_first          (lw_ws_req);
  lw_import    lw_ws_req_param  lw_ws_req_POST_first         (lw_ws_req);
  lw_import         const char* lw_ws_req_param_name         (lw_ws_req_param);
  lw_import         const char* lw_ws_req_param_value        (lw_ws_req_param);
  lw_import    lw_ws_req_param  lw_ws_req_param_next         (lw_ws_req_param);
  lw_import   lw_ws_req_cookie  lw_ws_req_cookie_first       (lw_ws_req);
  lw_import         const char* lw_ws_req_cookie_name        (lw_ws_req_cookie);
  lw_import         const char* lw_ws_req_cookie_value       (lw_ws_req_cookie);
  lw_import   lw_ws_req_cookie  lw_ws_req_cookie_next        (lw_ws_req_cookie);
  lw_import               void  lw_ws_req_set_cookie         (lw_ws_req, const char * name, const char * value);
  lw_import               void  lw_ws_req_set_cookie_attr    (lw_ws_req, const char * name, const char * value, const char * attributes);
  lw_import         const char* lw_ws_req_get_cookie         (lw_ws_req, const char * name);
  lw_import         const char* lw_ws_req_session_id         (lw_ws_req);
  lw_import               void  lw_ws_req_session_write      (lw_ws_req, const char * name, const char * value);
  lw_import         const char* lw_ws_req_session_read       (lw_ws_req, const char * name);
  lw_import               void  lw_ws_req_session_close      (lw_ws_req);
  lw_import  lw_ws_sessionitem  lw_ws_req_session_first      (lw_ws_req);
  lw_import         const char* lw_ws_sessionitem_name       (lw_ws_sessionitem);
  lw_import         const char* lw_ws_sessionitem_value      (lw_ws_sessionitem);
  lw_import  lw_ws_sessionitem  lw_ws_sessionitem_next       (lw_ws_sessionitem);
  lw_import         const char* lw_ws_req_GET                (lw_ws_req, const char * name);
  lw_import         const char* lw_ws_req_POST               (lw_ws_req, const char * name);
  lw_import         const char* lw_ws_req_body               (lw_ws_req);
  lw_import               void  lw_ws_req_disable_cache      (lw_ws_req);
  lw_import               long  lw_ws_req_idle_timeout       (lw_ws_req);
  lw_import               void  lw_ws_req_set_idle_timeout   (lw_ws_req, long seconds);  
/*lw_import               void  lw_ws_req_enable_dl_resuming (lw_ws_req);
  lw_import             lw_i64  lw_ws_req_reqrange_begin     (lw_ws_req);
  lw_import             lw_i64  lw_ws_req_reqrange_end       (lw_ws_req);
  lw_import               void  lw_ws_req_set_outgoing_range (lw_ws_req, lw_i64 begin, lw_i64 end);*/
"""

{.pop.}

# lw_addr_*
proc addr_new* (hostname, service:cstring): LW_Addr
proc addr_new_port* (hostname:cstring; port:clong): LW_Addr
proc addr_new_hint* (hostname,service:cstring; hints:clong): LW_Addr
proc addr_new_port_hint*(hostname:cstring; port,hints:clong): LW_Addr

const
  AddrTypeTCP* = 1i32
  AddrTypeUDP* = 2i32
  AddrHintIPV6* = 4i32

{.push importc:"lw_addr_$1".}
proc clone* (address:LW_Addr): LW_Addr
proc delete*(address:LW_Addr)
proc port* (address:LW_Addr):clong
proc set_port*(address:LW_Addr; port:clong)
proc `type`* (address:LW_Addr): cint
proc set_type* (address:LWAddr; ty:cint)
proc ready* (address:LWaddr): bool
proc resolve* (address:LWaddr):LWerror
proc ipv6* (address:LWaddr):bool
proc equal*(a,b:LWaddr):bool
# tostring
proc tostring* (`addr`:LWaddr):cstring
proc tag*(a:LWaddr):pointer
proc set_tag*(a:LWaddr;tag:pointer)


{.pop.}
# udp
#  typedef void (lw_callback * lw_udp_hook_data)(lw_udp, lw_addr, const char * buffer, size_t size);
type TUDPDataHook* = proc(udp:LW_UDP, `addr`:LW_Addr, buffer:cstring, size:csize)
#  typedef void (lw_callback * lw_udp_hook_error) (lw_udp, lw_error);
type TUDP_ErrorHook* = proc(udp:LW_UDP; error:LW_Error)


proc udp_new* (pump:LWPump): LW_UDP
{.push importc:"lw_udp_$1".}
proc delete* (udp:LW_UDP)
proc host* (udp:LW_UDP; port:clong)
proc host_filter* (udp:LW_UDP; filter: LW_Filter)
proc host_addr* (udp:LW_UDP; `addr`: LW_Addr)
proc hosting* (udp:LW_UDP): bool
proc unhost* (udp:LW_UDP)
proc port* (udp:LW_UDP): clong
proc send* (udp:LW_UDP; `addr`:LW_Addr, buffer:cstring, size:csize)
proc tag* (udp:LW_UDP): pointer
proc set_tag* (udp:LW_UDP; tag:pointer)

proc on_data* (udp:LW_UDP; hook:TUDP_DataHook)
proc on_error* (udp:LW_UDP; hook:TUDP_ErrorHook)

{.pop.}

const
  retryNow* = 1
  retryNever* = 2
  retryMoreData* = 3
  
 

# Stream
proc stream_new* (streamdef: ptr streamdef; pump: lw_pump): lw_stream
proc stream_from_tail* (data:pointer): lw_stream
{.push importc:"lw_stream_$1".}
proc delete* (s:lw_stream)
proc bytes_left* (s:lw_stream):csize
proc read* (s:lw_stream; bytes:csize)
proc begin_queue* (s:lw_stream)
proc queued* (s:lw_stream):csize
proc end_queue* (s:lw_stream)
proc end_queue_hb* (s:lw_stream; numHeadBuffers:cint; buffers:cstringarray; lengths:ptr csize)

proc write* (s:lw_stream; buffer:cstring; length:csize)
#proc write_text*(s:lw_stream; buffer:cstring)
proc writef* (s:lw_stream; buffer:cstring) {.varargs.}
proc writev* (s:lw_stream; format:cstring) {.varargs.}
proc write_stream*(dest,src:lw_stream; size:csize; deleteWhenFinished:bool)
proc write_file* (s:lw_stream; filename:cstring) 

proc retry* (s:lw_stream; `when`:cint) 
proc add_filter_upstream* (s, filter: lw_stream; deleteWithStream, closeTogether:bool)
proc add_filter_downstream*(s,filter: lw_stream; deleteWithStream, closeTogether:bool)
proc close* (s:lw_stream, immediate:bool)
proc tag* (s:lw_stream): pointer
proc set_tag*(s:lw_stream;tag:pointer)
proc pump*(s:lw_stream):lw_pump

discard """
/* Stream */

  typedef void (lw_callback * lw_stream_hook_data)
      (lw_stream, void * tag, const char * buffer, size_t length);

  lw_import void lw_stream_add_hook_data (lw_stream, lw_stream_hook_data, void * tag);
  lw_import void lw_stream_remove_hook_data (lw_stream, lw_stream_hook_data, void * tag);

  typedef void (lw_callback * lw_stream_hook_close) (lw_stream, void * tag);

  lw_import void lw_stream_add_hook_close (lw_stream, lw_stream_hook_close, void * tag);
  lw_import void lw_stream_remove_hook_close (lw_stream, lw_stream_hook_close, void * tag);

  /* For stream implementors */
"""

# stream_new
proc get_def* (stream:lw_stream): ptr streamdef

proc tail* (stream:lw_stream): pointer
# stream_from_tail

proc data* (stream:lw_stream; buffer:cstring; size:csize)

{.pop.}

{.pop.}

proc `$`* (e:LWerror|LWaddr):string = $ e.toString

proc address* (R:LW_WS_REQ): LW_ADDR {.importc:"lw_ws_req_addr".}
{.pop.}

#proc version* : string = 
#  let r = version_private()
#  result = $r
#  dealloc r

#proc stream* (some: lw_ws_req): lw_stream = cast[lw_stream](some)
