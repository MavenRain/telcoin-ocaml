(* The scale constants of [utils.rs:6-15]: a 10^9 precision, the ten-percent
   threshold at 10^8 on that scale, and the threshold's square as the penalty
   divisor. All Z: the penalty product reaches [10^16 * unused], past 63-bit
   for any unused gas above 461. *)
let min_gas_limit_threshold = 210_000
let precision = Z.of_int 1_000_000_000
let threshold = Z.of_int 100_000_000
let threshold_squared = Z.of_int 10_000_000_000_000_000

let penalty ~gas_limit ~gas_spent =
  if gas_limit <= min_gas_limit_threshold then 0
  else
    let limit = Z.of_int gas_limit in
    (* The clamp is u64's lower bound made explicit; in the executor's domain
       it is the identity. *)
    let spent = Z.of_int (max gas_spent 0) in
    let ratio = Z.div (Z.mul precision spent) limit in
    if Z.geq ratio threshold then 0
    else
      let unused = Z.sub limit spent in
      let inefficiency = Z.sub threshold ratio in
      (* Total: on this branch [spent < limit / 10], so [unused <= limit] fits
         [int], and [inefficiency^2 <= threshold_squared] bounds the quotient
         by [unused] (the .mli postcondition). *)
      Z.to_int
        (Z.div (Z.mul (Z.mul inefficiency inefficiency) unused) threshold_squared)
