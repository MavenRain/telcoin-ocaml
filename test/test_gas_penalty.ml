(* The gas-limit inefficiency penalty (chunk 31): {!Tn_evm.Gas_penalty} against
   telcoin's own vectors.

   Every expected value below is one of utils.rs's #[cfg(test)] vectors
   (test_gas_penalty_calculation and test_edge_cases) or was recomputed
   independently in exact integer arithmetic; the doc-table rows and the test
   vectors agree. Executor-level settlement of the penalty is test_executor.ml's
   telcoin-fee-split section; this file is the formula alone, where the gate and
   the threshold actually bite (at settlement-realistic spends the boundary is
   invisible, see the last case). *)

module Gas_penalty = Tn_evm.Gas_penalty

let check ~gas_limit ~gas_spent expected =
  Alcotest.(check int)
    (Printf.sprintf "penalty(%d, %d)" gas_limit gas_spent)
    expected
    (Gas_penalty.penalty ~gas_limit ~gas_spent)

(* The eight rows of utils.rs's own test_gas_penalty_calculation, which also
   reproduce its doc table. Kills any drift in the three scale constants: a
   10^8 -> 10^7 threshold, for one, moves every nonzero row. *)
let test_utils_rs_vectors () =
  check ~gas_limit:21_000 ~gas_spent:21_000 0;
  check ~gas_limit:210_000 ~gas_spent:21_000 0;
  check ~gas_limit:420_000 ~gas_spent:21_000 99_750;
  check ~gas_limit:1_000_000 ~gas_spent:21_000 610_993;
  check ~gas_limit:5_000_000 ~gas_spent:21_000 4_569_546;
  check ~gas_limit:10_000_000 ~gas_spent:21_000 9_564_282;
  check ~gas_limit:30_000_000 ~gas_spent:21_000 29_560_762;
  check ~gas_limit:60_000_000 ~gas_spent:21_000 59_559_881

(* The 210_000 exemption gate, at spends small enough for the quotient to be
   nonzero on the far side. Kills gate removal and a <=/< flip; utils.rs's own
   edge vectors ride along. The (210_001, 21_000) case is the honesty note:
   at a realistic spend the gate does NOT discriminate, both sides are 0. *)
let test_gate () =
  check ~gas_limit:210_000 ~gas_spent:0 0;
  check ~gas_limit:210_001 ~gas_spent:0 210_001;
  check ~gas_limit:210_000 ~gas_spent:100 0;
  check ~gas_limit:210_001 ~gas_spent:100 207_906;
  check ~gas_limit:210_000 ~gas_spent:10_000 0;
  check ~gas_limit:209_999 ~gas_spent:10_000 0;
  check ~gas_limit:210_001 ~gas_spent:10_000 54_876;
  check ~gas_limit:210_001 ~gas_spent:21_000 0

(* Ten percent usage is exempt, exactly and by flooring: 99_999/1_000_000
   floors onto the threshold. The nonzero near-anchors (9.9 and 9 percent)
   kill threshold-constant drift from the exempt side. *)
let test_threshold () =
  check ~gas_limit:1_000_000 ~gas_spent:100_000 0;
  check ~gas_limit:300_000 ~gas_spent:30_000 0;
  check ~gas_limit:1_000_000 ~gas_spent:99_999 0;
  check ~gas_limit:1_000_000 ~gas_spent:99_000 90;
  check ~gas_limit:1_000_000 ~gas_spent:90_000 9_100

(* The postcondition edge: at zero spend the quotient is exactly the unused
   gas, never more (the bound that makes the Z narrowing total and the Rust
   fallback dead). Kills a dropped 10^16 divisor, which would return
   10^16 * unused here. The totality corners pin the .mli's claims: a negative
   spend clamps to u64's floor, an over-limit spend lands past the exemption. *)
let test_bound_and_totality () =
  check ~gas_limit:1_000_000 ~gas_spent:0 1_000_000;
  check ~gas_limit:1_000_000 ~gas_spent:(-1) 1_000_000;
  check ~gas_limit:1_000_000 ~gas_spent:2_000_000 0

let () =
  Alcotest.run "gas_penalty"
    [
      ( "vectors",
        [
          Alcotest.test_case "the utils.rs vector table" `Quick test_utils_rs_vectors;
          Alcotest.test_case "the 210_000 gate" `Quick test_gate;
          Alcotest.test_case "ten percent is exempt" `Quick test_threshold;
          Alcotest.test_case "penalty never exceeds unused gas" `Quick
            test_bound_and_totality;
        ] );
    ]
