(* Hex to bytes and back, for tests that compare computed bytes against an
   oracle's hex rows. Shared the way batch_vectors.ml is: not listed in
   test/dune's (names ...), so dune links it into every test binary. It uses
   nothing but the stdlib, so it can also be copied into an isolated test
   directory by a dune rule.

   [decode] is TOTAL and fail-closed: [None] on any character outside the
   lowercase alphabet and on an odd nibble count, so a mistyped vector row
   surfaces as a red test rather than as a silently shorter byte string. *)

let encode s =
  String.to_seq s
  |> Seq.map (fun c -> Printf.sprintf "%02x" (Char.code c))
  |> List.of_seq |> String.concat ""

(* The nibble value IS the character's index in the alphabet, so there is no
   per-character match and no partial accessor. *)
let nibble c = String.index_opt "0123456789abcdef" c

let decode s =
  (* The buffer is local and nothing mutable escapes; 64 is a hint, since
     [Buffer] grows on demand. *)
  let buf = Buffer.create 64 in
  let step acc c =
    Option.bind acc (fun pending ->
        Option.map
          (fun lo ->
            (* [hi] and [lo] are each 0..15 by construction, so [hi * 16 + lo]
               is 0..255 and [Buffer.add_uint8] never truncates. *)
            Option.fold ~none:(Some lo)
              ~some:(fun hi ->
                Buffer.add_uint8 buf ((hi * 16) + lo);
                None)
              pending)
          (nibble c))
  in
  Option.bind (String.fold_left step (Some None) s) (fun pending ->
      Option.fold
        ~none:(Some (Buffer.contents buf))
        ~some:(fun (_ : int) -> None)
        pending)
