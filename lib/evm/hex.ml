let hex_digit n = String.get "0123456789abcdef" n

let of_bytes s =
  String.init (2 * String.length s) (fun j ->
      let b = Char.code (String.get s (j / 2)) in
      let nibble = if j land 1 = 0 then b lsr 4 else b land 0x0f in
      hex_digit nibble)
