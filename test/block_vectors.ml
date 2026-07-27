(* Golden vectors for the chunk-30 block header, shared by the chunk's test
   executables the way tx_vectors.ml and trie_vectors.ml are shared. Not listed
   in test/dune's (names ...): dune links it into every test binary.

   THE ORACLE, named with its exact provenance the way test_block_roots.ml names
   alloy-trie 0.9.5. The header below is Ethereum mainnet block 23068672
   (0x1600000), a post-Prague block (its requestsHash is present and is
   EMPTY_REQUESTS_HASH), fetched on 2026-07-26 from the public JSON-RPC endpoint
   https://ethereum-rpc.publicnode.com by

     eth_getBlockByNumber ["0x1600000", false]

   Every field below is the verbatim hex that call returned, and [block_hash] is
   the [hash] field it returned, computed by the network rather than by this
   port. It is an oracle for exactly one thing: the ORDER of the twenty-one
   fields of a post-Prague execution header and the byte-string versus scalar
   rule each one takes. That was the chunk's highest open risk, because
   alloy-consensus 1.8.3 is not among the extracted crates and the order in
   block_header.ml was derived from the EIP append sequence rather than read.

   A mainnet header cannot be produced by {!Tn_evm.Block_header.assemble} (its
   ommers_hash is a batch digest, its extra_data comes from the epoch boundary,
   its state root comes from the executed world), so the vector is consumed in
   two steps that together certify the module. See
   test_block_header.ml's "golden vector" section for the join. *)

let block_number = 23068672
let block_hash = "b70015517848ec72b5bb9721b1625eb11441c92b1871042f4e74eab3f4271970"
let parent_hash = "4e1122fe105dbf7a3b986bc11e55371fbb3aa13d2f9715bd5c6a5ee86b177e96"
let ommers_hash = "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"
let beneficiary = "4838b106fce9647bdf1e7877bf73ce8b0bad5f97"
let state_root = "def0bdee847c80b66aaa5b8957fe158df8b8d83d4af6001be2c2deb1c9837600"
let transactions_root = "5929af33a997cf3ccfd7f6f7b145b93dfaed1989bbe9f6c7e051e3b292aa427f"
let receipts_root = "35d5982a95179c3c8f146375b52d1b2129945f847a5cd77a5d9799eff5445dbe"

let logs_bloom =
  "79292ee2edb55b97b91123fbe6a05779fb4ab4e1dd563695b62967b84409b6bfd47d15baa3383aa1abb77bfb038e1d9dd6afac20dd97af752cd3be4f9b6c0facb4fbdd4acb033fa9fe336fee966eb8ea6cfc14dbd57f4973d5ddbc2e93a4f4f35b6130b3d77eddf6629efb14587c7d9b2463e0f5912cdef143e818bf571db2e1a275fbedbccac14f6d76656025fee6639507a5b1fb372b5cb6bfec7ea19caedfdb4f17969fffeb06f3dbf3c2bfc08f3b27e3a31d0014d646fdfd67de1c6ab9f9f7f25c4a11018d50e77f8b38726eb88feb75b64376afa6dff67de5ea67b6ea4f99f03dbecbc266b1a6fd929ca96d83a53d6eb513eb7a96feb64bcc32323776e9"

(* difficulty and base_fee_per_gas take the SCALAR rule, so they are carried as
   the full thirty-two big-endian bytes the port would hold in a [U256] and the
   encoder strips the leading zeros. A post-merge difficulty is zero. *)
let difficulty_be32 = String.make 32 '\000'
let base_fee_per_gas = 777968846
let gas_limit = 44912112
let gas_used = 17619894
let timestamp = 1754322215
let extra_data = "546974616e2028746974616e6275696c6465722e78797a29"
let mix_hash = "d90bcb30926ceaca2bffa538e449a920954ddc5bf2bea5a9794b35e646ae67df"

(* EIGHT raw bytes, not a scalar: the Rust field is a [B64]. This header's nonce
   is all zeros, which is exactly the case a scalar encoding would collapse to
   the single byte 0x80 and shorten the list's payload. *)
let nonce_be8 = String.make 8 '\000'
let withdrawals_root = "1a12f4063a53a08b62338ffd6ff250ebd81f3a741559c70869305ef49432da91"

(* The block's OWN sixteen withdrawals, as [(index, validator_index, address,
   amount)] in the order the block body lists them, from the same
   [eth_getBlockByNumber] response every other vector here was cut from.

   These are what turn [withdrawals_root] above from a regression constant into
   a real external oracle. The root is published by the network, so a
   [Withdrawal.encode_rlp] that ordered its four fields any other way, or that
   encoded the address as a scalar rather than as twenty fixed-width bytes,
   cannot reproduce it. That is the EIP-4895 field order certified rather than
   asserted. *)
let withdrawals =
  [
    (96539371, 760933, "d861f72137c15476c5d14f448e1a3d1de354f2d2", 19405837);
    (96539372, 760934, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19414832);
    (96539373, 760935, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19324994);
    (96539374, 760936, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19373796);
    (96539375, 760937, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19400117);
    (96539376, 760938, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19399769);
    (96539377, 760939, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 66252048);
    (96539378, 760940, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 18901764);
    (96539379, 760941, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19406642);
    (96539380, 760942, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19393284);
    (96539381, 760943, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19372591);
    (96539382, 760944, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19303797);
    (96539383, 760945, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19324949);
    (96539384, 760946, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19276979);
    (96539385, 760947, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19370168);
    (96539386, 760948, "b9d7934878b5fb9610b3fe8a5e441e8fad7e293f", 19419574);
  ]

let blob_gas_used = 0
let excess_blob_gas = 0

let parent_beacon_block_root =
  "6ffbfcd11a4987772fb2adcfa5433505dac2b1c5380d56fc6bb51bc91841048f"

let requests_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

(* ------------------------------------------------------------------ *)
(* Hex helpers, the same shape test_block_roots.ml uses.               *)
(* ------------------------------------------------------------------ *)

let hex s =
  let digit c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> 0
  in
  String.init
    (String.length s / 2)
    (fun i ->
      Char.chr ((digit (String.get s (2 * i)) lsl 4) lor digit (String.get s ((2 * i) + 1))))

let to_hex s =
  let buf = Buffer.create (2 * String.length s) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

(* ------------------------------------------------------------------ *)
(* The canonical encoder, written once and used twice.                 *)
(* ------------------------------------------------------------------ *)

(* The twenty-one chunks of a post-Prague execution header, in the order this
   module's vector certifies, with the byte-string rule and the scalar rule
   applied one line at a time. Every hash-shaped argument is RAW BYTES, the two
   scalars are raw big-endian bytes whose leading zeros the encoder strips, the
   five sizes are native ints, and [nonce] is eight raw bytes.

   This function is the joint between the two halves of the certification: the
   golden test hashes its output over the mainnet vector, and the agreement test
   compares its output over a TN header against
   {!Tn_evm.Block_header.encode_rlp}. Neither half alone certifies the module;
   together they do. *)
let encode_header ~parent_hash ~ommers_hash ~beneficiary ~state_root
    ~transactions_root ~receipts_root ~logs_bloom ~difficulty_be ~number
    ~gas_limit ~gas_used ~timestamp ~extra_data ~mix_hash ~nonce_be
    ~base_fee_per_gas_be ~withdrawals_root ~blob_gas_used ~excess_blob_gas
    ~parent_beacon_block_root ~requests_hash =
  Tn_rlp.Rlp.encode_list
    [
      Tn_rlp.Rlp.encode_bytes parent_hash;
      Tn_rlp.Rlp.encode_bytes ommers_hash;
      Tn_rlp.Rlp.encode_bytes beneficiary;
      Tn_rlp.Rlp.encode_bytes state_root;
      Tn_rlp.Rlp.encode_bytes transactions_root;
      Tn_rlp.Rlp.encode_bytes receipts_root;
      Tn_rlp.Rlp.encode_bytes logs_bloom;
      Tn_rlp.Rlp.encode_scalar difficulty_be;
      Tn_rlp.Rlp.encode_nat number;
      Tn_rlp.Rlp.encode_nat gas_limit;
      Tn_rlp.Rlp.encode_nat gas_used;
      Tn_rlp.Rlp.encode_nat timestamp;
      Tn_rlp.Rlp.encode_bytes extra_data;
      Tn_rlp.Rlp.encode_bytes mix_hash;
      Tn_rlp.Rlp.encode_bytes nonce_be;
      Tn_rlp.Rlp.encode_scalar base_fee_per_gas_be;
      Tn_rlp.Rlp.encode_bytes withdrawals_root;
      Tn_rlp.Rlp.encode_nat blob_gas_used;
      Tn_rlp.Rlp.encode_nat excess_blob_gas;
      Tn_rlp.Rlp.encode_bytes parent_beacon_block_root;
      Tn_rlp.Rlp.encode_bytes requests_hash;
    ]

(* The mainnet header of the vector, encoded through {!encode_header}. Its
   keccak is asserted equal to {!block_hash}, which the network computed. *)
let mainnet_header_rlp () =
  let base_fee_be =
    Tn_state.U256.to_be_bytes
      (Option.value ~default:Tn_state.U256.zero (Tn_state.U256.of_int base_fee_per_gas))
  in
  encode_header ~parent_hash:(hex parent_hash) ~ommers_hash:(hex ommers_hash)
    ~beneficiary:(hex beneficiary) ~state_root:(hex state_root)
    ~transactions_root:(hex transactions_root) ~receipts_root:(hex receipts_root)
    ~logs_bloom:(hex logs_bloom) ~difficulty_be:difficulty_be32 ~number:block_number
    ~gas_limit ~gas_used ~timestamp ~extra_data:(hex extra_data) ~mix_hash:(hex mix_hash)
    ~nonce_be:nonce_be8 ~base_fee_per_gas_be:base_fee_be
    ~withdrawals_root:(hex withdrawals_root) ~blob_gas_used ~excess_blob_gas
    ~parent_beacon_block_root:(hex parent_beacon_block_root)
    ~requests_hash:(hex requests_hash)
