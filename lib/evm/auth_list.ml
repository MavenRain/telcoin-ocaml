open Tn_types
module World_state = Tn_state.World_state
module Account = Tn_state.Account
module Delegation = Tn_state.Delegation
module U256 = Tn_state.U256
module Nonce = Tn_state.Nonce

type disposition =
  | Chain_id_mismatch
  | Nonce_saturated
  | Unrecoverable
  | Has_code
  | Nonce_mismatch
  | Applied of { refunded : bool }

let disposition_to_string = function
  | Chain_id_mismatch -> "chain_id_mismatch"
  | Nonce_saturated -> "nonce_saturated"
  | Unrecoverable -> "unrecoverable"
  | Has_code -> "has_code"
  | Nonce_mismatch -> "nonce_mismatch"
  | Applied { refunded } -> if refunded then "applied:refunded" else "applied:fresh"

(* PER_AUTH_BASE_COST ([revm-primitives] [eip7702.rs:5-9]). Never charged;
   only the refund difference below reads it. *)
let per_auth_base_cost = 12_500

type t = {
  world : World_state.t;
  warmed : Units.Address.t list;
  refunded_entries : int;
  dispositions : disposition list;
}

let world t = t.world
let warmed t = t.warmed
let dispositions t = t.dispositions

(* [pre_execution.rs:268-271]: refunded_accounts * (25000 - 12500). The 25000
   lives in {!Intrinsic} because it is a CHARGE; the 12500 lives here because
   it is not. *)
let refund t = t.refunded_entries * (Intrinsic.per_empty_account_cost - per_auth_base_cost)

(* Check 2's constant: the u64 ceiling, one below {!Authorization.make}'s bound
   ([pre_execution.rs:223-226] is an equality against [u64::MAX], not a range
   test). *)
let nonce_saturated = U256.sub (U256.two_pow 64) U256.one

(* The account's live nonce widened for check 6's 256-bit equality. A nonce is
   a non-negative [int] by construction, so the widening cannot fail; the
   [~default] is unreachable. *)
let word_of_nonce n = Option.value (U256.of_int (Nonce.to_int n)) ~default:U256.zero

(* Checks 4 through 9 for one entry that passed checks 1-3. Check 4's warming
   is the UNCONDITIONAL first effect ([pre_execution.rs:234-237] precedes
   [:239-250]): the authority joins [warmed] before checks 5 and 6 can skip.
   Check 5 reuses the four-way classification the executor's EIP-3607 arm
   matches on — [Contract] and [Undecodable] block (the latter is the
   documented conservative direction for magic-prefixed bytes that decode to
   nothing), empty code and an existing designator pass, which is what makes
   re-delegation an overwrite ([pre_execution.rs:239-245]). Check 6 compares
   the LIVE threaded nonce, so a duplicate authority needs consecutive nonces
   ([pre_execution.rs:247-250]). Check 7's predicate runs BEFORE the write —
   a fresh authority is delegated but earns nothing — and checks 8+9 are the
   single {!Account.delegate}, which sets the code and bumps the nonce in one
   move ([pre_execution.rs:252-265]). *)
let screened_step (world, warmed_rev, refunded_entries, disps_rev) sg scr =
  let authority = Authorization.authority scr in
  let warmed_rev = authority :: warmed_rev in
  let acct = World_state.account world authority in
  match Account.code_class acct with
  | Delegation.Contract | Delegation.Undecodable _ ->
      (world, warmed_rev, refunded_entries, Has_code :: disps_rev)
  | Delegation.Codeless | Delegation.Delegated _ ->
      if
        not
          (U256.equal (Authorization.screened_nonce scr) (word_of_nonce (Account.nonce acct)))
      then (world, warmed_rev, refunded_entries, Nonce_mismatch :: disps_rev)
      else
        (* KNOWN NARROWING of revm's check 7 ([pre_execution.rs:252-259]):
           revm also refunds an ALL-ZERO account that exists in its DB, but
           {!World_state.set_account} prunes absent-shaped accounts, so
           "all-zero yet present" is unrepresentable here and earns nothing
           (port nets 46000 where revm nets 36800). Reaching it needs a
           genesis alloc with an all-zero entry whose owner then signs an
           authorization; neither TN genesis has one. *)
        let refunded = not (Account.is_absent acct) in
        let delegated =
          Account.delegate acct (Authorization.address (Authorization.unsigned sg))
        in
        ( World_state.set_account world authority delegated,
          warmed_rev,
          (if refunded then refunded_entries + 1 else refunded_entries),
          Applied { refunded } :: disps_rev )

(* One entry. Checks 1 and 2 are re-stated so their dispositions are
   distinguishable — {!Authorization.screen} collapses revm's three [continue]s
   into one [None] — and [screen] then re-runs them as the single gate to the
   recovery, so a [None] here can only mean check 3. Checks 1-3 touch nothing:
   the three skip arms return the accumulator with only a disposition added. *)
let step ~chain_id ((world, warmed_rev, refunded_entries, disps_rev) as acc) sg =
  let auth = Authorization.unsigned sg in
  let auth_chain = Authorization.chain_id auth in
  if not (U256.is_zero auth_chain || U256.equal auth_chain chain_id) then
    (world, warmed_rev, refunded_entries, Chain_id_mismatch :: disps_rev)
  else if U256.equal (Authorization.nonce auth) nonce_saturated then
    (world, warmed_rev, refunded_entries, Nonce_saturated :: disps_rev)
  else
    Option.fold
      ~none:(world, warmed_rev, refunded_entries, Unrecoverable :: disps_rev)
      ~some:(screened_step acc sg)
      (Authorization.screen ~chain_id sg)

let apply ~world ~chain_id entries =
  let world, warmed_rev, refunded_entries, disps_rev =
    List.fold_left (step ~chain_id) (world, [], 0, []) entries
  in
  { world; warmed = List.rev warmed_rev; refunded_entries; dispositions = List.rev disps_rev }
