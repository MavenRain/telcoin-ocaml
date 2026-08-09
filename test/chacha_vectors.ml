(* Golden vectors for the chunk-41 leader-swap RNG, from the same Rust oracle
   run as header_vectors.ml (telcoin-network @
   5dbb764ee0f4d2fb89d3e57bc010ecde7445220d; rand 0.9.2, rand_chacha 0.9.0).
   Pure constants, linked into every test binary.

   Rust's [LeaderSwapTable::swap] (crates/consensus/primary/src/consensus/
   leader_schedule.rs:209-218) builds a 32-byte seed that is all zeros except
   for the leader round, widened from u32 to u64 and written LITTLE-ENDIAN
   into [seed_bytes[24..32]], seeds [StdRng::from_seed] with it (a passthrough
   newtype over [ChaCha12Rng]) and then makes exactly ONE draw:
   [good_nodes.choose(&mut rng)]. [choose] is [self[rng.random_range(..len)]],
   an EXCLUSIVE range that [UniformInt::sample_single] turns into the
   inclusive bound [len - 1] on the u32 sampler path.

   [seed] is recorded next to each row so a seeding bug is distinguishable
   from a sampler bug: if the seed matches and the index does not, the draw is
   wrong; if the seed does not match, the write is wrong.

   CH1 pins the degenerate one-good-node case, CH2 to CH4 vary the bound. CH5
   to CH7 hold the bound at four and vary the round across 0, 255 and 256, so
   a big-endian seed write is caught at the first byte boundary. CH8 uses
   [u32::MAX], which pins the full eight-byte little-endian write of the
   widened round and catches a four-byte write.

   [ch_neg_reference_index] is CH5's index. It is compared against what the
   house SplitMix64 [Tn_std.Prng] returns for the same round and bound: those
   two must DIFFER, or the row proves nothing about which RNG is wired in. *)

type row = {
  label : string;
  round : int64;
  good_nodes : int;
  seed : string;
  chosen : int;
}

let rows =
  [
  {
    label = "CH1";
    round = 1L;
    good_nodes = 1;
    seed = "0000000000000000000000000000000000000000000000000100000000000000";
    chosen = 0;
  };
  {
    label = "CH2";
    round = 1L;
    good_nodes = 2;
    seed = "0000000000000000000000000000000000000000000000000100000000000000";
    chosen = 1;
  };
  {
    label = "CH3";
    round = 1L;
    good_nodes = 3;
    seed = "0000000000000000000000000000000000000000000000000100000000000000";
    chosen = 1;
  };
  {
    label = "CH4";
    round = 1L;
    good_nodes = 4;
    seed = "0000000000000000000000000000000000000000000000000100000000000000";
    chosen = 2;
  };
  {
    label = "CH5";
    round = 0L;
    good_nodes = 4;
    seed = "0000000000000000000000000000000000000000000000000000000000000000";
    chosen = 1;
  };
  {
    label = "CH6";
    round = 255L;
    good_nodes = 4;
    seed = "000000000000000000000000000000000000000000000000ff00000000000000";
    chosen = 1;
  };
  {
    label = "CH7";
    round = 256L;
    good_nodes = 4;
    seed = "0000000000000000000000000000000000000000000000000001000000000000";
    chosen = 0;
  };
  {
    label = "CH8";
    round = 4294967295L;
    good_nodes = 4;
    seed = "000000000000000000000000000000000000000000000000ffffffff00000000";
    chosen = 3;
  };
  ]

let ch_neg_reference_index = 1
