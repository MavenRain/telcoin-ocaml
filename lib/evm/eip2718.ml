(* The EIP-2718 type-byte rule, shared by the receipt and transaction envelope
   encoders: typed prepends exactly one raw byte, type 0 prepends nothing
   (alloy-consensus 1.8.3 [src/transaction/legacy.rs:150-168] and
   [src/receipt/receipt2.rs:144-156]; alloy-eips 1.8.3
   [src/eip2718.rs:246-249]). *)

let frame ~type_byte body =
  if type_byte = 0 then body
  else
    (* [land 0xff] keeps [Char.chr] total; a type byte is one byte by
       definition and every caller here passes 1 or 2. *)
    String.make 1 (Char.chr (type_byte land 0xff)) ^ body
