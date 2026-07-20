open Tn_types
module U256 = Tn_state.U256

module Topics = struct
  type word = U256.t

  type t =
    | T0
    | T1 of word
    | T2 of word * word
    | T3 of word * word * word
    | T4 of word * word * word * word

  let arity = function
    | T0 -> Topic_count.Zero
    | T1 _ -> Topic_count.One
    | T2 _ -> Topic_count.Two
    | T3 _ -> Topic_count.Three
    | T4 _ -> Topic_count.Four

  (* Five arms, each calling [pop] exactly as many times as the constructor it
     returns takes arguments. Written out rather than folded over a count so
     that the arity and the payload cannot disagree: the compiler checks each
     arm builds the constructor its count names. *)
  let collect count ~pop source =
    let ( let* ) = Result.bind in
    match count with
    | Topic_count.Zero -> Ok (T0, source)
    | Topic_count.One ->
        let* a, source = pop source in
        Ok (T1 a, source)
    | Topic_count.Two ->
        let* a, source = pop source in
        let* b, source = pop source in
        Ok (T2 (a, b), source)
    | Topic_count.Three ->
        let* a, source = pop source in
        let* b, source = pop source in
        let* c, source = pop source in
        Ok (T3 (a, b, c), source)
    | Topic_count.Four ->
        let* a, source = pop source in
        let* b, source = pop source in
        let* c, source = pop source in
        let* d, source = pop source in
        Ok (T4 (a, b, c, d), source)

  let to_list = function
    | T0 -> []
    | T1 a -> [ a ]
    | T2 (a, b) -> [ a; b ]
    | T3 (a, b, c) -> [ a; b; c ]
    | T4 (a, b, c, d) -> [ a; b; c; d ]

  let equal a b =
    Topic_count.equal (arity a) (arity b)
    && List.equal U256.equal (to_list a) (to_list b)
end

type t = { address : Units.Address.t; topics : Topics.t; data : string }

let make ~address ~topics ~data = { address; topics; data }
let address t = t.address
let topics t = t.topics
let data t = t.data

let equal a b =
  Units.Address.equal a.address b.address
  && Topics.equal a.topics b.topics
  && String.equal a.data b.data

let hex_digit n = String.get "0123456789abcdef" n

let to_hex s =
  String.init (2 * String.length s) (fun j ->
      let b = Char.code (String.get s (j / 2)) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)

let to_string t =
  Printf.sprintf "log(%s, topics=[%s], data=%s)"
    (to_hex (Units.Address.to_bytes t.address))
    (String.concat "; " (List.map U256.to_hex (Topics.to_list t.topics)))
    (to_hex t.data)
