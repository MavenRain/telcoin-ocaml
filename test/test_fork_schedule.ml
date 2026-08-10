(* Tests for the fork level (Tn_evm.Spec) and the activation schedule
   (Tn_evm.Fork_schedule). Pure: no EVM, no state, no fixtures.

   The oracles are the two committed Telcoin genesis configs and revm's gate
   phrasing:
     - mainnet genesis.yaml declares "shanghaiTime: 0" and carries no cancunTime
       or pragueTime key at all, so every mainnet block is at Shanghai;
     - testnet genesis.yaml declares shanghaiTime, cancunTime and pragueTime all
       as 0, so every testnet block is at Prague;
     - revm gates a behavior with spec_id().is_enabled_in(SpecId::$min), which
       is ">= min", so a fork activates ON its activation timestamp and not the
       second after it.

   Two hazards are guarded on purpose. Every timestamp is built through [ts],
   which re-reads the value back out, so a rejected Int64 cannot silently become
   zero and pass a boundary case vacuously. Every schedule is consumed through
   [with_schedule], so a schedule that [make] rejected fails the case loudly
   instead of skipping its assertions. *)

module Spec = Tn_evm.Spec
module Fork_schedule = Tn_evm.Fork_schedule
module Timestamp = Tn_types.Units.Timestamp

let spec_t =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Spec.to_string s))
    (fun a b -> Int.equal (Spec.compare a b) 0)

let schedule_t =
  Alcotest.testable
    (fun fmt s -> Format.pp_print_string fmt (Fork_schedule.to_string s))
    Fork_schedule.equal

(* Equality on the error sum by an exhaustive rank, so a new variant is a
   compile error here rather than a silently unequal pair. *)
let error_rank = function
  | Fork_schedule.Cancun_before_shanghai -> 0
  | Fork_schedule.Prague_before_cancun -> 1
  | Fork_schedule.Prague_without_cancun -> 2

let error_t =
  Alcotest.testable
    (fun fmt e -> Format.pp_print_string fmt (Fork_schedule.error_to_string e))
    (fun a b -> Int.equal (error_rank a) (error_rank b))

let made_t = Alcotest.result schedule_t error_t

(* A timestamp that proves it survived the conversion: [Timestamp.of_sec]
   rejects a negative second, and a silent fallback to zero would make a
   boundary assertion pass for the wrong reason. *)
let ts n =
  let t = Option.value ~default:Timestamp.zero (Timestamp.of_sec n) in
  Alcotest.(check int64) (Printf.sprintf "timestamp %Ld is representable" n) n (Timestamp.to_sec t);
  t

(* Run [f] on an accepted schedule; a rejected one fails the case with the
   rejection printed, so no assertion is skipped in silence. *)
let with_schedule r f =
  Result.fold ~ok:f
    ~error:(fun e ->
      Alcotest.(check string)
        "the schedule must be accepted" "accepted"
        ("rejected: " ^ Fork_schedule.error_to_string e))
    r

(* Every fork level, produced through a match that is total on the sum: a new
   constructor makes this match partial, which the dev profile turns into a
   build failure, so the truth table below cannot stay silently short. *)
let all_specs =
  List.map
    (fun s -> match s with Spec.Shanghai -> s | Spec.Cancun -> s | Spec.Prague -> s)
    [ Spec.Shanghai; Spec.Cancun; Spec.Prague ]

(* The literal 3x3 table for [is_enabled spec ~from], written out rather than
   derived from [compare], so a flipped comparison has nothing to hide behind. *)
let enabled_table =
  [
    (Spec.Shanghai, Spec.Shanghai, true);
    (Spec.Shanghai, Spec.Cancun, false);
    (Spec.Shanghai, Spec.Prague, false);
    (Spec.Cancun, Spec.Shanghai, true);
    (Spec.Cancun, Spec.Cancun, true);
    (Spec.Cancun, Spec.Prague, false);
    (Spec.Prague, Spec.Shanghai, true);
    (Spec.Prague, Spec.Cancun, true);
    (Spec.Prague, Spec.Prague, true);
  ]

let test_spec_order_total () =
  Alcotest.(check int)
    "the table covers every ordered pair of the sum"
    (List.length all_specs * List.length all_specs)
    (List.length enabled_table);
  List.iter
    (fun (spec, from, expected) ->
      Alcotest.(check bool)
        (Printf.sprintf "is_enabled %s ~from:%s" (Spec.to_string spec) (Spec.to_string from))
        expected
        (Spec.is_enabled spec ~from))
    enabled_table;
  (* The order the table encodes, stated once directly. *)
  Alcotest.(check bool) "shanghai before cancun" true (Spec.compare Spec.Shanghai Spec.Cancun < 0);
  Alcotest.(check bool) "cancun before prague" true (Spec.compare Spec.Cancun Spec.Prague < 0);
  Alcotest.(check bool) "shanghai before prague" true (Spec.compare Spec.Shanghai Spec.Prague < 0);
  Alcotest.(check bool) "prague after shanghai" true (Spec.compare Spec.Prague Spec.Shanghai > 0);
  List.iter
    (fun s ->
      Alcotest.(check int) (Printf.sprintf "%s equals itself" (Spec.to_string s)) 0 (Spec.compare s s))
    all_specs;
  Alcotest.(check (list string))
    "each level names itself"
    [ "shanghai"; "cancun"; "prague" ]
    (List.map Spec.to_string all_specs)

let test_schedule_make_rejects () =
  Alcotest.(check made_t)
    "cancun earlier than shanghai"
    (Error Fork_schedule.Cancun_before_shanghai)
    (Fork_schedule.make ~shanghai:(ts 100L) ~cancun:(Some (ts 50L)) ~prague:None);
  Alcotest.(check made_t)
    "prague earlier than cancun"
    (Error Fork_schedule.Prague_before_cancun)
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:(Some (ts 100L)) ~prague:(Some (ts 50L)));
  Alcotest.(check made_t)
    "prague on a chain that never activates cancun"
    (Error Fork_schedule.Prague_without_cancun)
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:None ~prague:(Some (ts 100L)));
  (* The monotone schedule the boundary case uses is accepted, so the three
     rejections above are rejections and not a constructor that never builds. *)
  with_schedule
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:(Some (ts 100L)) ~prague:(Some (ts 200L)))
    (fun s ->
      Alcotest.(check string)
        "the monotone schedule reads back" "shanghai=0 cancun=100 prague=200"
        (Fork_schedule.to_string s));
  (* Equal activation times are monotone, not out of order. *)
  Alcotest.(check bool)
    "all three at the same second is accepted" true
    (Result.is_ok (Fork_schedule.make ~shanghai:(ts 7L) ~cancun:(Some (ts 7L)) ~prague:(Some (ts 7L))))

let test_active_at_boundaries () =
  with_schedule
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:(Some (ts 100L)) ~prague:(Some (ts 200L)))
    (fun s ->
      let at n = Fork_schedule.active_at s ~timestamp:(ts n) in
      Alcotest.(check spec_t) "ts=0 is shanghai" Spec.Shanghai (at 0L);
      Alcotest.(check spec_t) "ts=99 is shanghai" Spec.Shanghai (at 99L);
      Alcotest.(check spec_t) "ts=100 is cancun: activation is >=" Spec.Cancun (at 100L);
      Alcotest.(check spec_t) "ts=199 is cancun" Spec.Cancun (at 199L);
      Alcotest.(check spec_t) "ts=200 is prague: activation is >=" Spec.Prague (at 200L);
      Alcotest.(check spec_t) "ts=max is prague" Spec.Prague (at Int64.max_int))

(* The documented clamp: below the shanghai activation the answer is still
   Shanghai, because Spec.t has no earlier constructor to give. Unreachable on
   both committed configs, which activate shanghai at 0. *)
let test_active_at_clamps_below_shanghai () =
  with_schedule
    (Fork_schedule.make ~shanghai:(ts 50L) ~cancun:(Some (ts 100L)) ~prague:None)
    (fun s ->
      let at n = Fork_schedule.active_at s ~timestamp:(ts n) in
      Alcotest.(check spec_t) "ts=0 below shanghai is shanghai" Spec.Shanghai (at 0L);
      Alcotest.(check spec_t) "ts=49 below shanghai is shanghai" Spec.Shanghai (at 49L);
      Alcotest.(check spec_t) "ts=50 is shanghai" Spec.Shanghai (at 50L);
      Alcotest.(check spec_t) "ts=100 is cancun" Spec.Cancun (at 100L);
      Alcotest.(check spec_t) "a never-activated prague stays absent" Spec.Cancun (at Int64.max_int))

let test_mainnet_always_shanghai () =
  Alcotest.(check spec_t)
    "mainnet at 0 is shanghai" Spec.Shanghai
    (Fork_schedule.active_at Fork_schedule.mainnet ~timestamp:(ts 0L));
  Alcotest.(check spec_t)
    "mainnet at max is shanghai" Spec.Shanghai
    (Fork_schedule.active_at Fork_schedule.mainnet ~timestamp:(ts Int64.max_int));
  Alcotest.(check string)
    "mainnet activates shanghai only" "shanghai=0 cancun=never prague=never"
    (Fork_schedule.to_string Fork_schedule.mainnet);
  (* The named value and the smart constructor agree on the same genesis. *)
  Alcotest.(check made_t)
    "make accepts the mainnet genesis fields"
    (Ok Fork_schedule.mainnet)
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:None ~prague:None);
  Alcotest.(check bool)
    "mainnet is not testnet" false
    (Fork_schedule.equal Fork_schedule.mainnet Fork_schedule.testnet)

let test_testnet_always_prague () =
  Alcotest.(check spec_t)
    "testnet at 0 is prague" Spec.Prague
    (Fork_schedule.active_at Fork_schedule.testnet ~timestamp:(ts 0L));
  Alcotest.(check spec_t)
    "testnet at max is prague" Spec.Prague
    (Fork_schedule.active_at Fork_schedule.testnet ~timestamp:(ts Int64.max_int));
  Alcotest.(check string)
    "testnet activates all three at zero" "shanghai=0 cancun=0 prague=0"
    (Fork_schedule.to_string Fork_schedule.testnet);
  Alcotest.(check made_t)
    "make accepts the testnet genesis fields"
    (Ok Fork_schedule.testnet)
    (Fork_schedule.make ~shanghai:(ts 0L) ~cancun:(Some (ts 0L)) ~prague:(Some (ts 0L)))

let () =
  Alcotest.run "fork_schedule"
    [
      ( "spec",
        [ Alcotest.test_case "spec-order-total" `Quick test_spec_order_total ] );
      ( "schedule",
        [
          Alcotest.test_case "schedule-make-rejects" `Quick test_schedule_make_rejects;
          Alcotest.test_case "active-at-boundaries" `Quick test_active_at_boundaries;
          Alcotest.test_case "active-at-clamps-below-shanghai" `Quick
            test_active_at_clamps_below_shanghai;
          Alcotest.test_case "mainnet-always-shanghai" `Quick test_mainnet_always_shanghai;
          Alcotest.test_case "testnet-always-prague" `Quick test_testnet_always_prague;
        ] );
    ]
