(** Fault-injecting syscall tables. TEST ONLY.

    These live outside [tn_durable] on purpose: the production signature then
    carries no test-only value, and the fault seam is the vtable itself rather
    than a hook cut into the code under test.

    Each table is built over {!Tn_durable.Io_ops.real} and differs from it in
    exactly one respect, so a case that goes red under a table names the fault
    it injected and nothing else. Counting is per table value: [nth] is the
    [nth] call to the affected operation through THAT table, one-based. *)

val traced : sink:(string -> unit) -> Tn_durable.Io_ops.t
(** [traced ~sink] performs every call for real, and hands [sink] one line per
    call BEFORE making it, so a call that fails is still recorded. The line
    starts with the operation name, and carries the path or the length where
    the vtable is given one: ["openfile /a/b"], ["write 40"], ["fsync"],
    ["rename /a/b.tmp -> /a/b"]. The order of these lines IS the durability
    ordering a crash argument depends on. *)

type code =
  | Absent
      (** The failure a missing name produces: [ENOENT], obtained by asking the
          operating system about a path that cannot exist. *)
  | Contended
      (** The failure a held lock produces: [EAGAIN], obtained by reading an
          empty non-blocking pipe. *)

val fail_at : nth:int -> op:Tn_durable.Io.op -> code:code -> Tn_durable.Io_ops.t
(** [fail_at ~nth ~op ~code] makes the [nth] call to [op] fail with [code], and
    performs every other call for real.

    The failure is a GENUINE operating-system failure, provoked by a real call
    that cannot succeed, never a synthesised exception: this library raises
    nothing itself, which is what keeps the port's no-exceptions rule intact in
    the test tree as well.

    Two operations are indistinguishable at the vtable and are selected by
    their file-level name: a directory flush is [Fsync], not [Fsync_dir], and
    an existence question is [Stat]. Provoking [Contended] leaks the pipe it
    reads, which is bounded by the number of injections a case makes. *)

val short_write_at : nth:int -> bytes:int -> Tn_durable.Io_ops.t
(** [short_write_at ~nth ~bytes] lets the [nth] write accept only [bytes] of
    what it was offered, and every write after it accept nothing: a device that
    takes a prefix and then stops. A writer that loops correctly reports
    {!Tn_durable.Io.Short_write}; one that assumes the first count was the
    whole payload reports success over a truncated file. *)

val skip_fsync_at : nth:int -> Tn_durable.Io_ops.t
(** [skip_fsync_at ~nth] returns success from the [nth] flush without making
    it: a device that lies. Nothing above the vtable can observe this, which is
    the point - it models the one failure a counter cannot catch, and is used
    to prove that an ordering claim rests on the sequence of calls rather than
    on their return values. *)
