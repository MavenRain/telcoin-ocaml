(* The runnable vertical slice: stand up a committee of honest nodes, run the
   deterministic simulator to the horizon, and print the committed output plus an
   agreement check. Exit non-zero if a node hit an invariant-break error, the
   nodes disagreed, or nothing committed — so the binary doubles as a smoke test.

   Knobs come from optional flags — [--validators N] [--seed S] [--until-s T] —
   defaulting to a 4-validator, seed-42, 20 s run. This is imperative shell glue:
   it builds a known-good committee (a size the smart constructor cannot reject
   and keys that cannot collide), so the two startup lookups below are total. *)

open Tn_types
open Tn_consensus
open Tn_sim

let unwrap = function
  | Some x -> x
  | None -> failwith "tn_sim: unreachable — committee construction is fixed"

let dur ms = unwrap (Units.Duration.of_ms ms)
let short id = String.sub (Authority_id.to_hex id) 0 8

(* Scan argv for a [flag value] pair; a missing or unparseable value falls back
   to [default], so the parser is total for any argv. *)
let arg_scan flag parse default =
  let rec find = function
    | k :: v :: _ when String.equal k flag -> Option.value ~default (parse v)
    | _ :: rest -> find rest
    | [] -> default
  in
  find (Array.to_list Sys.argv)

let arg_int flag default = arg_scan flag int_of_string_opt default
let arg_int64 flag default = arg_scan flag Int64.of_string_opt default

(* A fixed committee and a secret-key lookup, keys derived from 0 .. size-1. *)
let build n =
  let sks = List.init n (fun i -> Tn_crypto.Secret_key.derive (Int64.of_int i)) in
  let authorities =
    List.map
      (fun sk ->
        Authority.make
          ~protocol_key:(Tn_crypto.Secret_key.public_key sk)
          ~execution_address:Units.Address.zero)
      sks
  in
  let committee =
    Result.fold ~ok:Fun.id
      ~error:(fun e -> failwith ("tn_sim: " ^ Committee.error_to_string e))
      (Committee.create ~epoch:Units.Epoch.zero authorities)
  in
  let sk_of id =
    unwrap
      (List.find_opt
         (fun sk ->
           Authority_id.equal
             (Authority_id.of_public_key (Tn_crypto.Secret_key.public_key sk))
             id)
         sks)
  in
  (committee, sk_of)

let node_error_to_string : Node.error -> string = function
  | Node.Certificate_equivocation (round, id) ->
      Printf.sprintf "certificate equivocation at round %s for %s"
        (Round.to_string round) (short id)
  | Node.Missing_parent d ->
      Printf.sprintf "missing parent %s" (Digests.Header_digest.to_hex d)
  | Node.Missing_parent_round round ->
      Printf.sprintf "missing parent round %s" (Round.to_string round)

let print_output sim self =
  List.iteri
    (fun i sd ->
      Printf.printf "  [%d] round %s  leader %s\n" i
        (Round.to_string (Sub_dag.leader_round sd))
        (short (Sub_dag.leader_author sd)))
    (Sim.committed sim self)

let () =
  (* size >= 2 keeps Committee.create total; until_s >= 1 keeps the horizon positive *)
  let size = max 2 (arg_int "--validators" 4) in
  let seed = arg_int64 "--seed" 42L in
  let until_s = max 1 (arg_int "--until-s" 20) in
  let committee, sk_of = build size in
  let cfg =
    Sim.config ~min_latency:(dur 5) ~max_latency:(dur 50)
      ~horizon:(dur (until_s * 1000)) ~max_steps:1_000_000 ~seed ()
  in
  let sim =
    Sim.create ~committee ~secret_key:sk_of ~proposer_config:Proposer.default_config
      ~sub_dags_per_schedule:100 ~gc_depth:50 ~config:cfg
  in
  let sim = Sim.run sim in
  let members = List.map Authority.id (Committee.authorities committee) in
  Printf.printf "telcoin-ocaml simulator — %d validators, seed %Ld, %d s horizon\n"
    size seed until_s;
  Printf.printf "delivered %d events over %d ms of simulated time\n" (Sim.steps sim)
    (Units.Duration.to_ms (Sim.elapsed sim));
  List.iteri
    (fun i id ->
      Printf.printf "  node %d (%s): %d commits\n" i (short id)
        (Sim.commit_count sim id))
    members;
  let fatal =
    Option.fold ~none:false
      ~some:(fun (id, e) ->
        Printf.printf "FATAL invariant break at node %s: %s\n" (short id)
          (node_error_to_string e);
        true)
      (Sim.error sim)
  in
  let agreed =
    match Sim.agreement sim with
    | Sim.Agree k ->
        Printf.printf "agreement: all nodes share a committed prefix of length %d\n" k;
        k > 0
    | Sim.Diverge { left; right; index } ->
        Printf.printf "DIVERGENCE: %s and %s disagree at commit index %d\n"
          (short left) (short right) index;
        false
  in
  (match members with
  | self :: _ ->
      Printf.printf "committed leader sequence (node 0):\n";
      print_output sim self;
      (* The execution seam: node 0's committed output folded into the consensus
         chain by the Noop engine. Each committed sub-DAG extends the chain by one
         block; the tip is the head the execution layer would build on next. *)
      let chain = Sim.executed sim self in
      Printf.printf "consensus chain (node 0): %d blocks; tip %s\n"
        (List.length chain)
        (Option.fold ~none:"(none)"
           ~some:(fun b ->
             Printf.sprintf "#%s %s"
               (Tn_execution.Consensus_block.Number.to_string
                  (Tn_execution.Consensus_block.number b))
               (Digests.Output_digest.to_hex
                  (Tn_execution.Consensus_block.digest b)))
           (Sim.execution_tip sim self))
  | [] -> ());
  exit (if (not fatal) && agreed then 0 else 1)
