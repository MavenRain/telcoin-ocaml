module Bcs = Tn_codec.Bcs

type rpc_info = { http : string; ws : string option }

type network_info = {
  pubkey : Var_bytes.t;
  multiaddrs : Var_bytes.t list;
  timestamp : int64;
  rpc : rpc_info option;
}

type t = { info : network_info; signature : Bls_signature.t }
type record_or_legacy = Current of t | Legacy of t

type error =
  | Both_layouts_rejected of { current : Bcs.error; legacy : Bcs.error }

let error_to_string = function
  | Both_layouts_rejected { current; legacy } ->
      Printf.sprintf "node record: current layout %s; legacy layout %s"
        (Bcs.error_to_string current)
        (Bcs.error_to_string legacy)

let make_rpc_info ~http ~ws = { http; ws }

let make_network_info ~pubkey ~multiaddrs ~timestamp ~rpc =
  { pubkey; multiaddrs; timestamp; rpc }

let make ~info ~signature = { info; signature }
let ( let* ) = Result.bind

let rpc_codec : rpc_info Bcs.t =
  Bcs.make
    ~write:(fun w i ->
      Bcs.write Bcs.string_utf8 w i.http;
      Bcs.write (Bcs.option Bcs.string_utf8) w i.ws)
    ~read:(fun r ->
      let* http = Bcs.read Bcs.string_utf8 r in
      let* ws = Bcs.read (Bcs.option Bcs.string_utf8) r in
      Ok { http; ws })

let addr_list : Var_bytes.t list Bcs.t = Bcs.list Var_bytes.codec

let write_common w (i : network_info) =
  Bcs.write Var_bytes.codec w i.pubkey;
  Bcs.write addr_list w i.multiaddrs;
  Bcs.Writer.u64 w i.timestamp

let read_common r =
  let* pubkey = Bcs.read Var_bytes.codec r in
  let* multiaddrs = Bcs.read addr_list r in
  let* timestamp = Bcs.Reader.u64 r in
  Ok (pubkey, multiaddrs, timestamp)

let codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      write_common w t.info;
      Bcs.write (Bcs.option rpc_codec) w t.info.rpc;
      Bcs.write Bls_signature.codec w t.signature)
    ~read:(fun r ->
      let* pubkey, multiaddrs, timestamp = read_common r in
      let* rpc = Bcs.read (Bcs.option rpc_codec) r in
      let* signature = Bcs.read Bls_signature.codec r in
      Ok { info = { pubkey; multiaddrs; timestamp; rpc }; signature })

let legacy_codec : t Bcs.t =
  Bcs.make
    ~write:(fun w t ->
      write_common w t.info;
      Bcs.write Bls_signature.codec w t.signature)
    ~read:(fun r ->
      let* pubkey, multiaddrs, timestamp = read_common r in
      let* signature = Bcs.read Bls_signature.codec r in
      Ok { info = { pubkey; multiaddrs; timestamp; rpc = None }; signature })

let decode_compat bytes =
  Result.fold
    ~ok:(fun t -> Ok (Current t))
    ~error:(fun current ->
      Result.fold
        ~ok:(fun t -> Ok (Legacy t))
        ~error:(fun legacy -> Error (Both_layouts_rejected { current; legacy }))
        (Bcs.decode legacy_codec bytes))
    (Bcs.decode codec bytes)

let rpc_equal a b =
  String.equal a.http b.http && Option.equal String.equal a.ws b.ws

let equal a b =
  Var_bytes.equal a.info.pubkey b.info.pubkey
  && List.equal Var_bytes.equal a.info.multiaddrs b.info.multiaddrs
  && Int64.equal a.info.timestamp b.info.timestamp
  && Option.equal rpc_equal a.info.rpc b.info.rpc
  && Bls_signature.equal a.signature b.signature
