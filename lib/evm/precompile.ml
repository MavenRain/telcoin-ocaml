module W = Tn_state.U256
module Address_word = Tn_state.Address_word

type response =
  | Not_a_precompile
  | Succeeded of { gas_used : int; output : string }
  | Rejected

(* ------------------------------------------------------------------ *)
(* Byte helpers                                                        *)
(* ------------------------------------------------------------------ *)

(* [len] rounded up to a whole number of 32-byte words. *)
let words len = (len + 31) / 32

(* revm's [calc_linear_cost_u32]: a flat base plus a per-word charge. *)
let linear_cost len base per_word = base + (per_word * words len)

(* Exactly [len] bytes of [s] from [off], zero-filled past the end of [s] and
   truncating a longer [s] (revm's fixed-width [right_pad::<LEN>]). *)
let slice_padded s off len =
  String.init len (fun i ->
      let j = off + i in
      if j >= 0 && j < String.length s then s.[j] else '\000')

(* [s] fitted to exactly [len] bytes: zero-padded on the right when short, and
   truncated when long — revm's variable [right_pad_vec] ([data.get(..len)]),
   which discards any trailing calldata past the declared header lengths. *)
let right_pad s len =
  if String.length s >= len then String.sub s 0 len
  else s ^ String.make (len - String.length s) '\000'

(* A big-endian byte string as a non-negative integer; leading zero bytes do not
   change the value, so a short string and its left-padding agree. *)
let z_of_be s =
  String.fold_left
    (fun acc c -> Z.add (Z.shift_left acc 8) (Z.of_int (Char.code c)))
    Z.zero s

(* The minimal big-endian encoding of [z] (no leading zero bytes; empty for
   zero), left-padded with zero bytes to at least [len] — revm's [left_pad_vec]
   over the modexp result, which keeps a result wider than the declared length. *)
let left_pad_be z len =
  let minimal_len = (Z.numbits z + 7) / 8 in
  let minimal =
    String.init minimal_len (fun i ->
        Char.chr
          (Z.to_int
             (Z.logand
                (Z.shift_right z ((minimal_len - 1 - i) * 8))
                (Z.of_int 0xff))))
  in
  if String.length minimal >= len then minimal
  else String.make (len - String.length minimal) '\000' ^ minimal

(* ------------------------------------------------------------------ *)
(* 0x04 IDENTITY, 0x02 SHA256, 0x03 RIPEMD160                          *)
(* ------------------------------------------------------------------ *)

let identity ~input ~gas_limit =
  let gas_used = linear_cost (String.length input) 15 3 in
  if gas_used > gas_limit then Rejected else Succeeded { gas_used; output = input }

let sha256 ~input ~gas_limit =
  let gas_used = linear_cost (String.length input) 60 12 in
  if gas_used > gas_limit then Rejected
  else
    Succeeded
      { gas_used; output = Digestif.SHA256.(to_raw_string (digest_string input)) }

(* revm returns the 20-byte digest left-padded into a 32-byte word. *)
let ripemd160 ~input ~gas_limit =
  let gas_used = linear_cost (String.length input) 600 120 in
  if gas_used > gas_limit then Rejected
  else
    let digest = Digestif.RMD160.(to_raw_string (digest_string input)) in
    Succeeded { gas_used; output = String.make 12 '\000' ^ digest }

(* ------------------------------------------------------------------ *)
(* 0x01 ECRECOVER                                                      *)
(* ------------------------------------------------------------------ *)

(* Flat 3000 gas. The 128-byte input is [msg | v | r | s]; [v] must be a 32-byte
   integer equal to 27 or 28. Malformed [v], or a signature that recovers no
   key, is a genuine success with empty output — only insufficient gas rejects.
   The recovered address is [keccak256(pubkey)[12..]] widened to a 32-byte word. *)
let ecrecover ~input ~gas_limit =
  let gas_used = 3000 in
  if gas_used > gas_limit then Rejected
  else
    let inp = slice_padded input 0 128 in
    let v_ok =
      String.for_all (Char.equal '\000') (String.sub inp 32 31)
      && (Char.code inp.[63] = 27 || Char.code inp.[63] = 28)
    in
    if not v_ok then Succeeded { gas_used; output = "" }
    else
      let msg = String.sub inp 0 32 in
      let recid = Char.code inp.[63] - 27 in
      let r = String.sub inp 64 32 in
      let s = String.sub inp 96 32 in
      let output =
        Option.fold ~none:""
          ~some:(fun pubkey ->
            let hash = Tn_keccak.to_bytes (Tn_keccak.digest pubkey) in
            String.make 12 '\000' ^ String.sub hash 12 20)
          (Secp256k1.recover ~msg ~recid ~r ~s)
      in
      Succeeded { gas_used; output }

(* ------------------------------------------------------------------ *)
(* 0x05 MODEXP (Berlin / EIP-2565)                                     *)
(* ------------------------------------------------------------------ *)

let z32 = Z.of_int 32
let z8 = Z.of_int 8
let z3 = Z.of_int 3
let z200 = Z.of_int 200

let zmax a b = if Z.geq a b then a else b

(* The high 32 bytes of the exponent as an integer: the [min(exp_len, 32)] bytes
   at offset [base_len] into the post-header data, right-padded with zeroes when
   the input runs short, which also handles an out-of-reach [base_len]. *)
let exp_high input ~base_len ~exp_len =
  let hb = if Z.geq exp_len z32 then 32 else Z.to_int exp_len in
  let start = Z.add (Z.of_int 96) base_len in
  let ilen = Z.of_int (String.length input) in
  z_of_be
    (String.init hb (fun i ->
         let idx = Z.add start (Z.of_int i) in
         if Z.geq idx ilen then '\000' else input.[Z.to_int idx]))

(* EIP-2565 iteration count with the Berlin multiplier of 8. *)
let iteration_count ~exp_len ~exp_highp =
  let ic =
    if Z.leq exp_len z32 && Z.equal exp_highp Z.zero then Z.zero
    else if Z.leq exp_len z32 then Z.sub (Z.of_int (Z.numbits exp_highp)) Z.one
    else
      Z.add
        (Z.mul z8 (Z.sub exp_len z32))
        (Z.sub (zmax Z.one (Z.of_int (Z.numbits exp_highp))) Z.one)
  in
  zmax ic Z.one

(* EIP-2565 gas: [max(200, mult_complexity * iteration_count / 3)], with
   [mult_complexity = ceil(max(base_len, mod_len) / 8) ^ 2]. Computed over [Z]
   so that a header declaring astronomical lengths overflows into a gas figure
   above any allowance rather than into an integer wrap. *)
let berlin_gas ~base_len ~exp_len ~mod_len ~exp_highp =
  let maxlen = zmax base_len mod_len in
  let ws = Z.div (Z.add maxlen (Z.of_int 7)) z8 in
  let mult = Z.mul ws ws in
  let iter = iteration_count ~exp_len ~exp_highp in
  zmax z200 (Z.div (Z.mul mult iter) z3)

let modexp ~input ~gas_limit =
  if 200 > gas_limit then Rejected
  else
    let base_len = z_of_be (slice_padded input 0 32) in
    let exp_len = z_of_be (slice_padded input 32 32) in
    let mod_len = z_of_be (slice_padded input 64 32) in
    let exp_highp = exp_high input ~base_len ~exp_len in
    let gas_z = berlin_gas ~base_len ~exp_len ~mod_len ~exp_highp in
    if Z.gt gas_z (Z.of_int gas_limit) then Rejected
    else
      let gas_used = Z.to_int gas_z in
      if Z.equal base_len Z.zero && Z.equal mod_len Z.zero then
        Succeeded { gas_used; output = "" }
      else
        (* The gas ceiling has bounded every length to a representable size. *)
        let bl = Z.to_int base_len
        and el = Z.to_int exp_len
        and ml = Z.to_int mod_len in
        let data =
          if String.length input > 96 then
            String.sub input 96 (String.length input - 96)
          else ""
        in
        let padded = right_pad data (bl + el + ml) in
        (* [right_pad] fitted [padded] to exactly [bl + el + ml], so the three
           reads split it with no remainder (revm's [split_at] chain, whose
           [debug_assert_eq!(modulus.len(), mod_len)] pins the modulus width). *)
        let base = z_of_be (String.sub padded 0 bl) in
        let exp = z_of_be (String.sub padded bl el) in
        let modulus = z_of_be (String.sub padded (bl + el) ml) in
        let result =
          if Z.equal modulus Z.zero then Z.zero else Z.powm base exp modulus
        in
        Succeeded { gas_used; output = left_pad_be result ml }

(* ------------------------------------------------------------------ *)
(* 0x09 BLAKE2F (EIP-152)                                              *)
(* ------------------------------------------------------------------ *)

(* A 64-bit word read little-endian from [s] at [off]. *)
let u64_le s off =
  let byte i = Int64.of_int (Char.code s.[off + i]) in
  Int64.logor (byte 0)
    (Int64.logor
       (Int64.shift_left (byte 1) 8)
       (Int64.logor
          (Int64.shift_left (byte 2) 16)
          (Int64.logor
             (Int64.shift_left (byte 3) 24)
             (Int64.logor
                (Int64.shift_left (byte 4) 32)
                (Int64.logor
                   (Int64.shift_left (byte 5) 40)
                   (Int64.logor
                      (Int64.shift_left (byte 6) 48)
                      (Int64.shift_left (byte 7) 56)))))))

(* [x] as 8 little-endian bytes. *)
let u64_le_bytes x =
  String.init 8 (fun i ->
      Char.chr
        (Int64.to_int
           (Int64.logand (Int64.shift_right_logical x (i * 8)) 0xffL)))

(* The 4-byte big-endian round count. *)
let u32_be s off =
  (Char.code s.[off] lsl 24)
  lor (Char.code s.[off + 1] lsl 16)
  lor (Char.code s.[off + 2] lsl 8)
  lor Char.code s.[off + 3]

(* The input is exactly [4 | h(64) | m(128) | t0(8) | t1(8) | f(1)] = 213 bytes.
   The round count is charged before the flag is validated, matching revm's
   order, so an under-funded call is rejected for gas even when the flag is also
   malformed. *)
let blake2f ~input ~gas_limit =
  if String.length input <> 213 then Rejected
  else
    let rounds = u32_be input 0 in
    if rounds > gas_limit then Rejected
    else
      let flag = Char.code input.[212] in
      if flag <> 0 && flag <> 1 then Rejected
      else
        let final = flag = 1 in
        let h = Array.init 8 (fun i -> u64_le input (4 + (i * 8))) in
        let m = Array.init 16 (fun i -> u64_le input (68 + (i * 8))) in
        let t0 = u64_le input 196 and t1 = u64_le input 204 in
        let h' = Blake2.compress ~rounds ~h ~m ~t0 ~t1 ~final in
        Succeeded
          {
            gas_used = rounds;
            output = String.concat "" (Array.to_list (Array.map u64_le_bytes h'));
          }

(* ------------------------------------------------------------------ *)
(* Dispatch                                                            *)
(* ------------------------------------------------------------------ *)

(* A precompile address is [0x0…0N] for a small [N], so its word is exactly [N]
   and fits an [int]; any real 160-bit address does not, giving [None]. *)
let invoke address ~input ~gas_limit =
  Option.fold ~none:Not_a_precompile
    ~some:(fun n ->
      match n with
      | 1 -> ecrecover ~input ~gas_limit
      | 2 -> sha256 ~input ~gas_limit
      | 3 -> ripemd160 ~input ~gas_limit
      | 4 -> identity ~input ~gas_limit
      | 5 -> modexp ~input ~gas_limit
      | 9 -> blake2f ~input ~gas_limit
      | _ -> Not_a_precompile)
    (W.to_int (Address_word.to_word address))
