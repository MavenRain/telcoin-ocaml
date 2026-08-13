type node = Primary | Worker of int
type error = Missing_leading_slash of { name : string }

let error_to_string = function
  | Missing_leading_slash { name } ->
      Printf.sprintf "protocol name %S does not start with '/'" name

let owned_protocol name =
  if String.starts_with ~prefix:"/" name then Ok name
  else Error (Missing_leading_slash { name })

(* "/tn-primary-{suffix}{chain}/{version}" and
   "/tn-worker-{id}-{suffix}{chain}/{version}": the worker id sits directly
   after the role, before the per-protocol suffix (GT:662-665). *)
let build ~node ~infix ~chain_id ~version =
  let role =
    match node with
    | Primary -> "/tn-primary-"
    | Worker id -> Printf.sprintf "/tn-worker-%d-" id
  in
  owned_protocol (Printf.sprintf "%s%s%d/%s" role infix chain_id version)

let req_res_protocol ~node ~chain_id =
  build ~node ~infix:"" ~chain_id ~version:"0.0.2"

let kad_protocol ~node ~chain_id =
  build ~node ~infix:"kad-" ~chain_id ~version:"0.0.1"

let sync_protocol ~node ~chain_id =
  build ~node ~infix:"sync-" ~chain_id ~version:"0.0.1"

let peer_exchange_protocol ~node ~chain_id =
  build ~node ~infix:"peer-exchange-" ~chain_id ~version:"0.0.1"

let gossip_protocol_id_prefix ~chain_id =
  Printf.sprintf "/tn-meshsub-%d" chain_id
