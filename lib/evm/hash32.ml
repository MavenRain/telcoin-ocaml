(* Re-export: the module moved to the leaf library tn_hash32 in chunk 32 so
   that tn_rand can name the seed type without depending on tn_evm (which now
   sits ABOVE tn_rand: the committee shuffle consumes the RNG). This alias
   keeps every existing [Hash32.]/[Tn_evm.Hash32] reference and the type
   equality [Tn_evm.Hash32.t = Tn_hash32.Hash32.t]. *)

include Tn_hash32.Hash32
