(** The durable checkpoint: the execution side's small artefact, published by
    rename at [<root>/checkpoint].

    {2 The container}

    {v
      offset  size  field        value
      0x00       8  magic        "TNCKPT\x00\x00"
      0x08       4  format       u32be 1
      0x0C       8  generation   u64be, strictly increasing across publishes
      0x14       4  len          u32be L
      0x18       8  body_tag     BLAKE2B(payload)[0..8)
      0x20       L  payload      BCS(Checkpoint.t), see {!Checkpoint_codec}
    v}

    That is [Tn_durable.Atomic_file]'s container with this module's magic in it,
    so the crash argument is the one that module already makes: [checkpoint.tmp]
    is written, flushed, renamed over [checkpoint], and the directory is
    flushed, in that order and with exactly two flushes, and [checkpoint.tmp] is
    never read - {!load} sweeps it first, so a temp left by a crash is discarded
    rather than adopted.

    {2 The one invariant this module adds}

    A checkpoint and the consensus store beside it are two durable artefacts,
    written at two different instants, and the shell protocol files the record
    strictly BEFORE it executes. The cross-artefact fact that follows is that a
    checkpoint's last-executed block is always at or below the store's durable
    tip, and always the block the store holds at that height. {!save} maintains
    it at the one instant it could be broken - the publish - rather than
    diagnosing it later at resume, which is why {!save} takes the store and why
    {!Ahead} and {!Unknown_block} are write-time refusals that spend no byte and
    no flush. *)

(** What a reader found at a root: either nothing has ever been published there,
    or one complete checkpoint has, at a known generation. There is no third
    answer, and in particular no "something damaged" arm - damage is an
    {!error}, so a caller cannot fold it into the fresh-node branch by
    accident. *)
type load =
  | Absent
      (** No checkpoint has ever been published at this root. The caller pairs
          this with [Tn_driver.Checkpoint.genesis], which is the fresh-node
          branch of the resumed-versus-fresh split. *)
  | Loaded of { checkpoint : Tn_driver.Checkpoint.t; generation : int }
      (** The published checkpoint and the generation it was published at. *)

(** Why a publish or a read could not be honoured. Seven arms, deliberately not
    collapsed: the first four are damage or refusal at a layer below this one,
    and the last three are this module's own cross-artefact rules, which fire
    before any byte is spent. *)
type error =
  | Io of Tn_durable.Io.error
      (** The operating system refused a call outside the container layer. *)
  | File of Tn_durable.Atomic_file.error
      (** The container refused: a foreign magic, an unsupported format, a
          payload that does not match its own tag, a truncated file. *)
  | Decode of Tn_codec.Bcs.error
      (** The payload framed correctly and is not a checkpoint. *)
  | Trailing of { left : int }
      (** The payload decoded and had bytes left over. A canonical encoding
          admits none, so the count is named rather than ignored. *)
  | Ahead of { watermark : int; durable_tip : int }
      (** WRITE-TIME refusal. A checkpoint whose last-executed height exceeds
          the store's durable tip cannot be published, because publishing it
          would record that the node executed a block the store does not hold -
          the one state from which a resumed driver would replay a shortened
          chain. Refused before a byte is written. *)
  | Unknown_block of { number : int }
      (** WRITE-TIME refusal. The store holds no record at the checkpoint's
          last-executed height, or holds one under a different digest: a
          checkpoint and a store from two different runs. Refused before a byte
          is written. *)
  | Generation_regressed of { stored : int; offered : int }
      (** The generation the publish would carry is not strictly above the one
          already on disk, so publishing it would make the counter say a newer
          file is older. Reachable only at the container's own u64be ceiling,
          where no strictly greater generation exists. *)

val error_to_string : error -> string
(** A one-line rendering of an {!error}, for diagnostics and test failure
    messages. *)

val save :
  ?ops:Tn_durable.Io_ops.t ->
  dir:string ->
  store:Tn_durable_store.Consensus_store_disk.t ->
  Tn_driver.Checkpoint.t ->
  (int, error) result
(** [save ~dir ~store checkpoint] refuses {!Ahead} and {!Unknown_block} BEFORE
    writing a byte, then publishes at the stored generation plus one and answers
    the new generation.

    Always flushed, exactly twice, whatever changed: upstream flushes its
    equivalent slots only on an epoch change, which makes the durability of a
    within-epoch checkpoint a function of when the epoch happens to roll. The
    cost of the stronger rule is one file flush and one directory flush per
    publish, and the count is an assertable equality rather than a claim.

    [ops] defaults to the stock system-call table; a caller supplies its own
    only to inject a fault. *)

val load : ?ops:Tn_durable.Io_ops.t -> dir:string -> unit -> (load, error) result
(** [load ~dir ()] answers {!Absent} when the canonical name has never existed,
    which means a fresh node and never a silent rewind.

    A canonical file that fails its magic, its format or its body tag is
    {!File}, and emphatically NOT {!Absent}: answering {!Absent} would send the
    caller to [Checkpoint.genesis] and rewind a populated node to epoch zero at
    block zero, which is the one recovery outcome worse than refusing to
    start. A stale [checkpoint.tmp] is swept before anything is read. *)
