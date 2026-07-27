(* The chunk-30 execution-layer header: the epoch-boundary commitment, the
   withdrawal RLP, the three repurposed fields, the twenty-one-element header
   RLP and its hash.

   THE GOLDEN VECTOR, and why it takes two tests. The order of the twenty-one
   header fields was this chunk's highest open risk: alloy-consensus 1.8.3 is
   not among the extracted crates, so block_header.ml's order was DERIVED from
   the EIP append sequence rather than read. A mainnet header cannot be produced
   by {!Tn_evm.Block_header.assemble} (its ommers_hash is a batch digest, its
   extra_data comes from the epoch boundary, its state root is taken over the
   world the block itself produced), so the vector is consumed in two steps:

     1. [header_rlp_reproduces_a_real_mainnet_block_hash] encodes the twenty-one
        fields of Ethereum mainnet block 23068672 through
        {!Block_vectors.encode_header} and asserts the keccak equals the hash the
        network published. That certifies the ORDER and the byte-string versus
        scalar rule of each position, against an oracle this port did not
        compute.
     2. [encode_rlp_agrees_with_the_certified_encoder] applies the SAME function
        to a TN header's own accessors and asserts byte equality with
        {!Tn_evm.Block_header.encode_rlp}. That transfers the certification onto
        the module.

   Neither half alone is enough; together they close the risk. A third test
   pins each position by content, which is what catches an adjacent swap
   introduced later in only one of the two encoders.

   OTHER ORACLES: [Tn_trie.Trie.empty_root] is alloy's EMPTY_WITHDRAWALS
   0x56e81f...b421, already pinned against alloy-trie 0.9.5 in
   test_block_roots.ml.

   The nonempty withdrawals root IS externally certified, and the claim that it
   could not be was wrong. alloy-trie's ordered_trie_root_with_encoder is indeed
   not among the extracted crate sources, but no crate was ever needed: the same
   mainnet block this file already roots its header argument in publishes both
   its sixteen withdrawals AND its withdrawalsRoot. So
   [test_withdrawals_root_reproduces_a_published_root] feeds
   [Block_vectors.withdrawals] through [Withdrawal.make] and
   [Block_roots.withdrawals_root] and checks the network's own
   [Block_vectors.withdrawals_root]. That certifies the EIP-4895 field order,
   the address being twenty fixed-width bytes rather than a scalar, and the
   RLP(index) trie keying, none of which a regression constant could tell apart.

   The two-withdrawal root below stays a regression pin, because that list is
   synthetic; it is now backed by the certified encoder rather than standing
   alone. *)

open Block_fixtures
module Bloom = Tn_evm.Bloom
module Block_execution = Tn_evm.Block_execution
module Block_header = Tn_evm.Block_header
module Block_roots = Tn_evm.Block_roots
module Hash32 = Tn_evm.Hash32
module Receipt = Tn_evm.Receipt
module Rlp = Tn_rlp.Rlp
module System_contracts = Tn_evm.System_contracts
module Trie = Tn_trie.Trie
module Withdrawal = Tn_evm.Withdrawal

let assembled = function
  | Ok header -> header
  | Error e -> Alcotest.failf "unexpected assembly error: %s" (Block_header.error_to_string e)

let run_ok = function
  | Ok outcome -> outcome
  | Error e -> Alcotest.failf "unexpected block error: %s" (Block_execution.error_to_string e)

let hash32 bytes =
  match Hash32.of_bytes bytes with
  | Some h -> h
  | None -> Alcotest.failf "fixture is %d bytes, not 32" (String.length bytes)

let withdrawal ~index ~validator_index ~address ~amount =
  match Withdrawal.make ~index ~validator_index ~address ~amount with
  | Some w -> w
  | None -> Alcotest.fail "fixture withdrawal was refused"

(* A twenty-byte address written as forty hex characters, which is how the
   mainnet withdrawal vector records them. *)
let address_of_hex s =
  match Address.of_bytes (hex s) with
  | Some a -> a
  | None -> Alcotest.failf "address fixture %s is not %d bytes" s Address.length

(* ------------------------------------------------------------------ *)
(* A block to assemble headers from.                                   *)
(* ------------------------------------------------------------------ *)

(* Two transfers of different sizes, so the transactions root, the receipts root
   and the state root are all distinct from each other and from the empty
   trie. *)
let spine_envelopes =
  [
    legacy_envelope ~signer:31 ~gas_limit:60_000 ~gas_price:100 ~value:1_234 ();
    legacy_envelope ~signer:32 ~gas_limit:60_000 ~gas_price:100 ~value:5_678 ();
  ]

let spine_world () = fund (System_contracts.predeploy World_state.empty) spine_envelopes

let assemble_with ctx =
  let pre, outcome = run_ok (Block_execution.execute (spine_world ()) ~context:ctx spine_envelopes) in
  (pre, outcome, Block_header.assemble ~context:ctx ~outcome)

(* ================================================================== *)
(* 1. The epoch boundary decides three fields together.                *)
(* ================================================================== *)

let alice = address_of 0x11
let bob = address_of 0x22

(* A REGRESSION pin, not an external oracle: see this file's header. It is the
   root of the two-withdrawal list below, in that order. *)
let two_withdrawals_root_hex =
  "48bf0f6ea52b2ce2105e32f87f8e016a9f894b7c8464a2a0ef0d1b48fe0938b2"

let test_close_epoch_pairs_extra_data_with_withdrawals () =
  let empty_hex = to_hex Trie.empty_root in
  Alcotest.(check string)
    "Trie.empty_root is alloy's EMPTY_WITHDRAWALS"
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" empty_hex;
  (* Open: EMPTY extra data, not thirty-two zero bytes. *)
  let open_commitment = Epoch_boundary.commitment Epoch_boundary.Open in
  Alcotest.(check int) "open extra_data is EMPTY" 0
    (String.length (Epoch_boundary.extra_data open_commitment));
  Alcotest.(check int) "open withdrawals" 0
    (List.length (Epoch_boundary.withdrawals open_commitment));
  Alcotest.(check string) "open withdrawals_root" empty_hex
    (to_hex (Epoch_boundary.withdrawals_root open_commitment));
  (* Closing: the randomness verbatim, the list unchanged, a real root. *)
  let randomness = hash32 (String.init 32 (fun i -> Char.chr (0xa0 + i))) in
  let w0 = withdrawal ~index:0 ~validator_index:0 ~address:alice ~amount:3 in
  let w1 = withdrawal ~index:0 ~validator_index:0 ~address:bob ~amount:5 in
  let closing = Epoch_boundary.Closing { randomness; withdrawals = [ w0; w1 ] } in
  let closing_commitment = Epoch_boundary.commitment closing in
  Alcotest.(check bool) "Open is not closing" false (Epoch_boundary.is_closing Epoch_boundary.Open);
  Alcotest.(check bool) "Closing is" true (Epoch_boundary.is_closing closing);
  Alcotest.(check string)
    "closing extra_data is the randomness verbatim"
    (to_hex (Hash32.to_bytes randomness))
    (to_hex (Epoch_boundary.extra_data closing_commitment));
  Alcotest.(check bool)
    "closing withdrawals are the list unchanged" true
    (List.equal Withdrawal.equal [ w0; w1 ] (Epoch_boundary.withdrawals closing_commitment));
  Alcotest.(check string)
    "closing withdrawals_root" two_withdrawals_root_hex
    (to_hex (Epoch_boundary.withdrawals_root closing_commitment));
  Alcotest.(check bool)
    "and it is NOT the empty-withdrawals constant" false
    (String.equal empty_hex (to_hex (Epoch_boundary.withdrawals_root closing_commitment)));
  (* The decode side of the same 0/32/error discipline. *)
  let render =
    Result.fold ~error:Epoch_boundary.error_to_string ~ok:(fun b ->
        match b with
        | Epoch_boundary.Open -> "open"
        | Epoch_boundary.Closing { randomness; withdrawals } ->
            Printf.sprintf "closing %s with %d" (to_hex (Hash32.to_bytes randomness))
              (List.length withdrawals))
  in
  Alcotest.(check string) "empty extra data, no withdrawals" "open"
    (render (Epoch_boundary.of_extra_data "" ~withdrawals:[]));
  Alcotest.(check string)
    "32 bytes of extra data"
    (Printf.sprintf "closing %s with 2" (to_hex (Hash32.to_bytes randomness)))
    (render
       (Epoch_boundary.of_extra_data (Hash32.to_bytes randomness) ~withdrawals:[ w0; w1 ]));
  Alcotest.(check string) "31 bytes is refused" "extra data length 31 (expected 0 or 32)"
    (render (Epoch_boundary.of_extra_data (String.make 31 '\000') ~withdrawals:[]));
  Alcotest.(check string) "withdrawals without a close are refused"
    "1 withdrawals on an open boundary"
    (render (Epoch_boundary.of_extra_data "" ~withdrawals:[ w0 ]))

(* The withdrawal RLP is a four-element list with the fields in EIP-4895 order.
   The fixture uses distinct index and validator_index (3 and 9) so a
   transposition of the two adjacent scalars is visible. *)
let test_withdrawal_rlp_shape_and_root_ordering () =
  let w = withdrawal ~index:3 ~validator_index:9 ~address:alice ~amount:7 in
  let items =
    match Rlp.decode_exact (Withdrawal.encode_rlp w) with
    | Ok (Rlp.List items) -> items
    | Ok (Rlp.Str _) -> Alcotest.fail "a withdrawal must encode as a list"
    | Error e -> Alcotest.failf "withdrawal RLP does not decode: %s" (Rlp.error_to_string e)
  in
  Alcotest.(check int) "four elements" 4 (List.length items);
  let render = function
    | Rlp.Str s -> to_hex s
    | Rlp.List _ -> "nested"
  in
  Alcotest.(check (list string))
    "index, validator_index, address (20 raw bytes), amount"
    [ "03"; "09"; to_hex (Address.to_bytes alice); "07" ]
    (List.map render items);
  (* The root, and its order sensitivity. Sorting inside withdrawals_root would
     make the ascending-address obligation the deferred rewards machinery owes
     (gas_accumulator.rs:123-158) untestable. *)
  let a = withdrawal ~index:0 ~validator_index:0 ~address:alice ~amount:3 in
  let b = withdrawal ~index:0 ~validator_index:0 ~address:bob ~amount:5 in
  Alcotest.(check string) "the empty list is the empty trie" (to_hex Trie.empty_root)
    (to_hex (Block_roots.withdrawals_root []));
  Alcotest.(check bool)
    "swapping two withdrawals changes the root" false
    (String.equal
       (Block_roots.withdrawals_root [ a; b ])
       (Block_roots.withdrawals_root [ b; a ]));
  Alcotest.(check string)
    "and the list order is the caller's" two_withdrawals_root_hex
    (to_hex (Block_roots.withdrawals_root [ a; b ]))

(* The EIP-4895 encoding certified against the network rather than against
   ourselves: mainnet block 23068672's own sixteen withdrawals must root to the
   withdrawalsRoot that block publishes. This is the oracle the chunk first
   recorded as unavailable. It was, in fact, already in the block the header
   vector was cut from.

   It discriminates far more than a regression constant can. Any permutation of
   the four withdrawal fields, an address encoded as a scalar instead of twenty
   fixed-width bytes (fifteen of these sixteen share one address whose leading
   byte is 0xb9, so a scalar would still be twenty bytes and a shape check alone
   would not notice), a non-minimal integer, or a trie keyed by anything but
   RLP(index) all fail to reach this root. *)
let test_withdrawals_root_reproduces_a_published_root () =
  let ws =
    List.map
      (fun (index, validator_index, address_hex, amount) ->
        withdrawal ~index ~validator_index ~address:(address_of_hex address_hex) ~amount)
      Block_vectors.withdrawals
  in
  Alcotest.(check int) "the block published sixteen withdrawals" 16 (List.length ws);
  Alcotest.(check string)
    "Block_roots.withdrawals_root reproduces mainnet 23068672's withdrawalsRoot"
    Block_vectors.withdrawals_root
    (to_hex (Block_roots.withdrawals_root ws));
  (* Non-vacuity of the vector itself: the published root is order sensitive, so
     the certified list is genuinely pinned rather than accidentally matching. *)
  let swapped =
    match ws with
    | first :: second :: rest -> (second :: first :: rest)
    | ([] | [ _ ]) as short -> short
  in
  Alcotest.(check bool)
    "swapping the first two withdrawals leaves the published root" false
    (String.equal Block_vectors.withdrawals_root (to_hex (Block_roots.withdrawals_root swapped)))

(* ================================================================== *)
(* 2. The assembled header.                                            *)
(* ================================================================== *)

(* ommers_hash is the consensus BATCH DIGEST and never keccak(rlp([])); the
   nonce is (epoch << 32) | round; the difficulty is
   (batch_index << 16) | worker_id. Telcoin's own engine test pins the last of
   these with worker id 0 (crates/engine/tests/it/main.rs:1080-1103). *)
let test_the_three_repurposed_fields () =
  let d = batch_digest32 (String.init 32 (fun i -> Char.chr (0xd0 + i))) in
  let ctx = context ~epoch:7 ~round:9 ~batch_digest:d ~batch_index:3 ~worker_id:2 () in
  let _, _, header = assemble_with ctx in
  let h = assembled header in
  Alcotest.(check int) "nonce epoch" 7
    (Units.Epoch.to_int (Units.Sequence_number.epoch (Block_header.nonce h)));
  Alcotest.(check int) "nonce round" 9
    (Tn_types.Round.to_int (Units.Sequence_number.round (Block_header.nonce h)));
  Alcotest.(check bool)
    "ommers_hash is the batch digest" true
    (Digests.Batch_digest.equal (Block_header.ommers_hash h) d);
  Alcotest.(check bool)
    "and is NOT keccak(rlp([]))" false
    (String.equal
       (Digest.to_bytes (Digests.Batch_digest.to_digest (Block_header.ommers_hash h)))
       (Hash32.to_bytes Block_header.empty_ommer_root));
  Alcotest.(check string)
    "empty_ommer_root is still the pinned constant"
    "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
    (Hash32.to_hex Block_header.empty_ommer_root);
  Alcotest.(check int) "difficulty is (3 << 16) | 2" 196_610
    (get (U256.to_int (Block_header.difficulty h)));
  Alcotest.(check bool)
    "and it is the position's own word" true
    (U256.equal (Block_header.difficulty h)
       (Batch_position.word (Block_header.position h)));
  (* The structurally constant fields. *)
  Alcotest.(check int) "blob_gas_used" 0 (Block_header.blob_gas_used h);
  Alcotest.(check int) "excess_blob_gas" 0 (Block_header.excess_blob_gas h);
  Alcotest.(check string) "requests_hash is sha256(\"\")"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (Hash32.to_hex Block_header.empty_requests_hash);
  Alcotest.(check bool)
    "the header carries it" true
    (Hash32.equal (Block_header.requests_hash h) Block_header.empty_requests_hash);
  Alcotest.(check string) "withdrawals_root on an open boundary is the empty trie"
    (to_hex Trie.empty_root)
    (Hash32.to_hex (Block_header.withdrawals_root h));
  Alcotest.(check int) "and the list is empty" 0 (List.length (Block_header.withdrawals h))

(* The state root and the transactions root come from ONE outcome. Assembling
   from the pre-block world instead is the shape of a fold that threads the
   wrong world, and it is exactly the bug a state_root PARAMETER would have
   permitted at every call site. *)
let test_state_root_and_transactions_root_come_from_one_outcome () =
  let ctx = context () in
  let pre, outcome, header = assemble_with ctx in
  let h = assembled header in
  Alcotest.(check string)
    "state root is the root of the world this block produced"
    (to_hex (Block_roots.state_root (Block_execution.world outcome)))
    (to_hex (Hash32.to_bytes (Block_header.state_root h)));
  Alcotest.(check string)
    "transactions root is the root of this block's transactions"
    (to_hex (Block_roots.transactions_root_of (Block_execution.transactions outcome)))
    (to_hex (Hash32.to_bytes (Block_header.transactions_root h)));
  Alcotest.(check string)
    "receipts root is the root of this block's receipts"
    (to_hex (Block_roots.receipts_root (Block_execution.receipts outcome)))
    (to_hex (Hash32.to_bytes (Block_header.receipts_root h)));
  (* Non-vacuity: the pre-block world and the post-transaction world really do
     differ, so taking the root of the wrong one is a visible mistake. *)
  Alcotest.(check bool)
    "the two worlds differ" false
    (String.equal
       (Block_roots.state_root (Block_execution.Pre_block.world pre))
       (Block_roots.state_root (Block_execution.world outcome)));
  Alcotest.(check int) "two transactions executed" 2
    (List.length (Block_execution.transactions outcome));
  Alcotest.(check bool)
    "and the bloom came from the outcome too" true
    (Bloom.equal (Block_header.logs_bloom h) (Block_execution.logs_bloom outcome));
  Alcotest.(check int) "as did gas_used"
    (Block_execution.gas_used outcome)
    (Block_header.gas_used h)

(* A closing block's world has not had the epoch-close state transitions
   applied, so its state root would be a lie. The refusal is at the ASSEMBLER
   and not in the fold: the fold is genuinely correct for a closing block, which
   the second half asserts by running both and comparing everything. *)
let test_a_closing_block_will_not_be_assembled () =
  let randomness = hash32 (String.init 32 (fun i -> Char.chr (0xb0 + i))) in
  let closing =
    Epoch_boundary.Closing
      {
        randomness;
        withdrawals = [ withdrawal ~index:0 ~validator_index:0 ~address:alice ~amount:4 ];
      }
  in
  let open_ctx = context () in
  let closing_ctx = context ~boundary:closing () in
  let world = spine_world () in
  let open_pre, open_outcome =
    run_ok (Block_execution.execute world ~context:open_ctx spine_envelopes)
  in
  let closing_pre, closing_outcome =
    run_ok (Block_execution.execute world ~context:closing_ctx spine_envelopes)
  in
  Alcotest.(check int) "the fold is identical: gas" (Block_execution.gas_used open_outcome)
    (Block_execution.gas_used closing_outcome);
  Alcotest.(check int) "the fold is identical: receipts"
    (List.length (Block_execution.receipts open_outcome))
    (List.length (Block_execution.receipts closing_outcome));
  Alcotest.(check string)
    "the fold is identical: world"
    (to_hex (Block_roots.state_root (Block_execution.world open_outcome)))
    (to_hex (Block_roots.state_root (Block_execution.world closing_outcome)));
  Alcotest.(check string)
    "and the pre-block phase is identical too"
    (to_hex (Block_roots.state_root (Block_execution.Pre_block.world open_pre)))
    (to_hex (Block_roots.state_root (Block_execution.Pre_block.world closing_pre)));
  Alcotest.(check string)
    "the closing block is refused at the assembler"
    "the epoch-close state transitions are deferred, so a closing block's state \
     root is not yet computable"
    (Result.fold ~ok:(fun _ -> "assembled") ~error:Block_header.error_to_string
       (Block_header.assemble ~context:closing_ctx ~outcome:closing_outcome));
  Alcotest.(check bool)
    "while the otherwise identical open block assembles" true
    (Result.is_ok (Block_header.assemble ~context:open_ctx ~outcome:open_outcome))

(* ================================================================== *)
(* 3. The header RLP.                                                  *)
(* ================================================================== *)

(* Step one of the golden-vector argument: the canonical encoder reproduces a
   real block hash the network computed. *)
let test_header_rlp_reproduces_a_real_mainnet_block_hash () =
  Alcotest.(check string)
    (Printf.sprintf "keccak of the RLP of mainnet block %d" Block_vectors.block_number)
    Block_vectors.block_hash
    (Tn_keccak.to_hex (Tn_keccak.digest (Block_vectors.mainnet_header_rlp ())))

(* Step two: the module's encoder is that encoder, applied to a TN header. *)
let encode_through_the_certified_encoder h =
  let nonce_be =
    let word = Units.Sequence_number.to_int64 (Block_header.nonce h) in
    String.init 8 (fun i ->
        Char.chr (Int64.to_int (Int64.logand (Int64.shift_right_logical word ((7 - i) * 8)) 0xffL)))
  in
  Block_vectors.encode_header
    ~parent_hash:(Tn_keccak.to_bytes (Block_header.parent_hash h))
    ~ommers_hash:(Digest.to_bytes (Digests.Batch_digest.to_digest (Block_header.ommers_hash h)))
    ~beneficiary:(Address.to_bytes (Block_header.beneficiary h))
    ~state_root:(Hash32.to_bytes (Block_header.state_root h))
    ~transactions_root:(Hash32.to_bytes (Block_header.transactions_root h))
    ~receipts_root:(Hash32.to_bytes (Block_header.receipts_root h))
    ~logs_bloom:(Bloom.to_bytes (Block_header.logs_bloom h))
    ~difficulty_be:(U256.to_be_bytes (Block_header.difficulty h))
    ~number:(Block_header.number h) ~gas_limit:(Block_header.gas_limit h)
    ~gas_used:(Block_header.gas_used h) ~timestamp:(Block_header.timestamp h)
    ~extra_data:(Block_header.extra_data h)
    ~mix_hash:(U256.to_be_bytes (Block_header.mix_hash h))
    ~nonce_be
    ~base_fee_per_gas_be:(U256.to_be_bytes (Block_header.base_fee_per_gas h))
    ~withdrawals_root:(Hash32.to_bytes (Block_header.withdrawals_root h))
    ~blob_gas_used:(Block_header.blob_gas_used h)
    ~excess_blob_gas:(Block_header.excess_blob_gas h)
    ~parent_beacon_block_root:
      (Digest.to_bytes
         (Digests.Output_digest.to_digest (Block_header.parent_beacon_block_root h)))
    ~requests_hash:(Hash32.to_bytes (Block_header.requests_hash h))

let test_encode_rlp_agrees_with_the_certified_encoder () =
  let ctx = context ~number:4_567 ~timestamp:1_700_000_123 ~gas_limit:30_000_000 ~basefee:7
      ~prevrandao:0x99 ~batch_index:3 ~worker_id:2 ~epoch:7 ~round:9 ()
  in
  let _, _, header = assemble_with ctx in
  let h = assembled header in
  Alcotest.(check string)
    "the module's twenty-one chunks are the certified encoder's"
    (to_hex (encode_through_the_certified_encoder h))
    (to_hex (Block_header.encode_rlp h));
  Alcotest.(check string)
    "and the hash is keccak of them"
    (Tn_keccak.to_hex (Tn_keccak.digest (Block_header.encode_rlp h)))
    (Tn_keccak.to_hex (Block_header.hash h))

(* Every position pinned by CONTENT, with values chosen to be mutually
   distinguishable: the nonce is all zeros (where a scalar encoding would
   collapse to the single byte 0x80), the difficulty is a trimmed scalar, and
   number, gas_limit, gas_used and timestamp are four different integers.

   HONEST LIMIT: the mutually indistinguishable class is THREE positions, not
   the two first recorded here. 17 (blob_gas_used) and 18 (excess_blob_gas) are
   both the constant zero, and 12 (extra_data) joins them because
   [Block_header.assemble] refuses every Closing boundary, so extra_data is
   provably the empty string in any header this port can currently build, and
   [Rlp.encode_bytes ""] is the same single byte 0x80 as [Rlp.encode_nat 0]. A
   transposition among {12, 17, 18} is therefore invisible to BOTH halves of the
   argument above: the golden half never runs the port's encoder, and the
   agreement half compares two encoders that both see 0x80 in all three slots.

   That is latent rather than harmless. The moment the epoch-close arm lands,
   telcoin puts 32 bytes of close-epoch randomness in extra_data
   ([block.rs:970]), and a 12-for-17 transposition would serialise that
   randomness where blob_gas_used belongs, producing a wrong block hash with no
   test turning red. Closing it needs a header whose extra_data is nonempty,
   which needs the deferred Closing arm; it is recorded here so the chunk that
   lands that arm inherits the obligation rather than rediscovering it. *)
let test_header_rlp_is_a_21_element_list_in_the_pinned_order () =
  let d = batch_digest32 (String.init 32 (fun i -> Char.chr (0x60 + i))) in
  let ctx =
    context ~number:4_567 ~timestamp:1_700_000_123 ~gas_limit:29_000_000 ~basefee:7
      ~prevrandao:0x99 ~batch_digest:d ~batch_index:5 ~worker_id:4 ~epoch:0 ~round:0 ()
  in
  let _, outcome, header = assemble_with ctx in
  let h = assembled header in
  let items =
    match Rlp.decode_exact (Block_header.encode_rlp h) with
    | Ok (Rlp.List items) -> items
    | Ok (Rlp.Str _) -> Alcotest.fail "a header must encode as a list"
    | Error e -> Alcotest.failf "header RLP does not decode: %s" (Rlp.error_to_string e)
  in
  Alcotest.(check int) "twenty-one elements" 21 (List.length items);
  let render = function
    | Rlp.Str s -> to_hex s
    | Rlp.List _ -> "nested"
  in
  let scalar_hex word =
    let bytes = U256.to_be_bytes word in
    let rec trim i = if i < String.length bytes && Char.code (String.get bytes i) = 0 then trim (i + 1) else i in
    let start = trim 0 in
    to_hex (String.sub bytes start (String.length bytes - start))
  in
  let nat_hex n = scalar_hex (u n) in
  Alcotest.(check (list string))
    "each of the twenty-one positions, by content"
    [
      to_hex (Tn_keccak.to_bytes parent_hash);
      to_hex (Digest.to_bytes (Digests.Batch_digest.to_digest d));
      to_hex (Address.to_bytes coinbase);
      to_hex (Block_roots.state_root (Block_execution.world outcome));
      to_hex (Block_roots.transactions_root_of (Block_execution.transactions outcome));
      to_hex (Block_roots.receipts_root (Block_execution.receipts outcome));
      to_hex (Bloom.to_bytes (Block_execution.logs_bloom outcome));
      nat_hex ((5 * 65536) + 4);
      nat_hex 4_567;
      nat_hex 29_000_000;
      nat_hex (Block_execution.gas_used outcome);
      nat_hex 1_700_000_123;
      "";
      to_hex (U256.to_be_bytes (u 0x99));
      "0000000000000000";
      nat_hex 7;
      to_hex Trie.empty_root;
      "";
      "";
      to_hex (Digest.to_bytes (Digests.Output_digest.to_digest consensus_root));
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    ]
    (List.map render items);
  (* The nonce is EIGHT raw bytes even when it is zero: a scalar encoding would
     have collapsed position 14 to the empty string above. *)
  Alcotest.(check int) "the nonce occupies eight bytes" 8
    (String.length (match List.nth items 14 with Rlp.Str s -> s | Rlp.List _ -> ""));
  Alcotest.(check int) "the bloom occupies 256" 256
    (String.length (match List.nth items 6 with Rlp.Str s -> s | Rlp.List _ -> ""))

let () =
  Alcotest.run "block-header"
    [
      ( "epoch-boundary",
        [
          Alcotest.test_case "close_epoch pairs extra_data with withdrawals" `Quick
            test_close_epoch_pairs_extra_data_with_withdrawals;
          Alcotest.test_case "withdrawal RLP shape and root ordering" `Quick
            test_withdrawal_rlp_shape_and_root_ordering;
          Alcotest.test_case "withdrawals root reproduces a published mainnet root" `Quick
            test_withdrawals_root_reproduces_a_published_root;
        ] );
      ( "assembly",
        [
          Alcotest.test_case "the three repurposed fields" `Quick test_the_three_repurposed_fields;
          Alcotest.test_case "state root and transactions root come from one outcome" `Quick
            test_state_root_and_transactions_root_come_from_one_outcome;
          Alcotest.test_case "a closing block will not be assembled" `Quick
            test_a_closing_block_will_not_be_assembled;
        ] );
      ( "header-rlp",
        [
          Alcotest.test_case "the canonical order reproduces a real mainnet block hash" `Quick
            test_header_rlp_reproduces_a_real_mainnet_block_hash;
          Alcotest.test_case "encode_rlp agrees with the certified encoder" `Quick
            test_encode_rlp_agrees_with_the_certified_encoder;
          Alcotest.test_case "twenty-one elements, each pinned by content" `Quick
            test_header_rlp_is_a_21_element_list_in_the_pinned_order;
        ] );
    ]
