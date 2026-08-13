let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

(* The character for a digit value, without indexing syntax: fold the alphabet
   carrying the position. [None] is unreachable for a digit under 58, which is
   all this module produces, and the caller keeps the string unchanged rather
   than substituting a wrong glyph. *)
let char_of_digit i =
  snd
    (String.fold_left
       (fun (k, found) c -> (k + 1, if k = i then Some c else found))
       (0, None) alphabet)

(* Drop leading zero digits so the loop terminates on the empty list. *)
let rec strip = function
  | [] -> []
  | d :: rest -> if d = 0 then strip rest else d :: rest

(* One long-division step over big-endian base-256 digits. The divisor is the
   nonzero literal 58, so the division is total; [cur] is at most
   57 * 256 + 255 = 14847 and never leaves OCaml's int range. *)
let divmod58 digits =
  let step (quotient, rem) d =
    let cur = (rem * 256) + d in
    ((cur / 58) :: quotient, cur mod 58)
  in
  let rev_quotient, rem = List.fold_left step ([], 0) digits in
  (strip (List.rev rev_quotient), rem)

let leading_zeros s =
  snd
    (String.fold_left
       (fun (stopped, n) c ->
         if stopped || c <> '\000' then (true, n) else (false, n + 1))
       (false, 0) s)

let encode s =
  let digits = List.of_seq (Seq.map Char.code (String.to_seq s)) in
  let rec go ds acc =
    match ds with
    | [] -> acc
    | _ :: _ ->
        let quotient, rem = divmod58 ds in
        go quotient
          (Option.fold ~none:acc
             ~some:(fun c -> String.make 1 c ^ acc)
             (char_of_digit rem))
  in
  String.make (leading_zeros s) '1' ^ go (strip digits) ""
