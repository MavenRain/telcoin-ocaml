module Epoch = struct
  type t = int

  let u32_max = 0xffff_ffff
  let zero = 0
  let of_int n = if n >= 0 && n <= u32_max then Some n else None
  let to_int t = t
  let succ t = if t >= u32_max then u32_max else t + 1
  let equal = Int.equal
  let compare = Int.compare
  let to_string = string_of_int
end

module Stake = struct
  type t = int

  let zero = 0
  let one = 1
  let of_int n = if n >= 0 then Some n else None
  let to_int t = t
  let add = ( + )
  let ( >= ) = Stdlib.( >= )
  let compare = Int.compare
  let to_string = string_of_int
end

module Timestamp = struct
  type t = int64

  let zero = 0L
  let of_sec s = if Int64.compare s 0L >= 0 then Some s else None
  let to_sec t = t
  let max a b = if Int64.compare a b >= 0 then a else b

  (* Add a whole-second offset, saturating at [Int64.max_int] so the result
     stays a valid (non-negative) timestamp — the drift-tolerance window
     [now + tolerance]. A negative offset is clamped to no change; the sole
     caller passes a non-negative tolerance. *)
  let add_secs t n =
    if n <= 0 then t
    else
      let n64 = Int64.of_int n in
      if Int64.compare t (Int64.sub Int64.max_int n64) > 0 then Int64.max_int
      else Int64.add t n64

  let equal = Int64.equal
  let compare = Int64.compare
  let to_string = Int64.to_string
end

module Duration = struct
  type t = int

  let zero = 0
  let of_ms n = if n >= 0 then Some n else None
  let to_ms t = t
  let add = ( + )

  (* Total: the representation is a non-negative int, so truncating division by
     two stays in range and needs no smart constructor. *)
  let half t = t / 2

  let compare = Int.compare
end

module Sequence_number = struct
  type t = int64

  let of_epoch_round e r =
    Int64.logor
      (Int64.shift_left (Int64.of_int (Epoch.to_int e)) 32)
      (Int64.of_int (Round.to_int r))

  let to_int64 t = t

  let epoch t =
    (* The high 32 bits are a valid u32 epoch by construction; the default is
       unreachable and present only to keep the accessor total. *)
    Epoch.of_int (Int64.to_int (Int64.shift_right_logical t 32))
    |> Option.value ~default:Epoch.zero

  let round t =
    Round.of_int (Int64.to_int (Int64.logand t 0xffff_ffffL))
    |> Option.value ~default:Round.genesis

  let equal = Int64.equal
  let compare = Int64.compare
end

module Worker_id = struct
  type t = int

  let u16_max = 0xffff
  let zero = 0
  let of_int n = if n >= 0 && n <= u16_max then Some n else None
  let to_int t = t
  let equal = Int.equal
  let compare = Int.compare
end

module Address = struct
  type t = string

  let length = 20
  let of_bytes s = if String.length s = length then Some s else None
  let to_bytes t = t
  let zero = String.make length '\000'
  let equal = String.equal
  let compare = String.compare
end
