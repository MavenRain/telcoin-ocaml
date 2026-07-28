(** [shuffle_new_committee] ([block.rs:428-482]) as a pure total function:
    deterministic in the pool's ARRIVAL order (the registry's per-status
    return order, [Active ++ PendingActivation ++ PendingExit], never
    pre-sorted, [block.rs:513-521, 560-562]), the committee size, and the 32
    randomness bytes that seed the RNG verbatim ([block.rs:438-443]). *)

val shuffle :
  pool:Registry_abi.Validator_info.t list ->
  committee_size:int ->
  randomness:Hash32.t ->
  Tn_types.Units.Address.t list
(** In Rust's order ([block.rs:445-482]): partition the pool on
    [currentStatus = PendingExit] ([block.rs:448-450], [Pending_activation]
    rides the active side); when the active side falls short of
    [committee_size], [Tn_rand.Rand_seq.choose_multiple] draws the missing
    count from the pending-exit side and appends it ([block.rs:456-463]),
    consuming the RNG {e before} the shuffle; when the active side suffices,
    the pending-exit validators are dropped and no top-up draw is consumed.
    Then a Fisher-Yates over the whole assembled list, [i] from [len - 1]
    down to [1] with [Tn_rand.Std_rng.random_range_inclusive ~bound:i] and a
    swap ([block.rs:466-470]); the map to [validatorAddress] happens AFTER
    the shuffle ([block.rs:474-475]); finally truncate to [committee_size]
    ([block.rs:477-478]).

    NO error on an undersized or empty pool: the short list is returned and
    rejection is the on-chain [concludeEpoch] call's business
    ([block.rs:453-463] has no local check; ground truth line 218). Total:
    empty and singleton pools shuffle to themselves, and a non-positive
    [committee_size] truncates to the empty list (a negative size has no Rust
    image; [usize] cannot go below zero).

    NOT sorted here: membership and RNG-determined order are this function's
    output. The ascending-address sort telcoin applies to the committee
    happens at {e encode} time, in [Epoch_close]'s [concludeEpoch] calldata
    step ([block.rs:394-395]), never inside the shuffle. *)
