(** Single-writer enforcement over a store root.

    Two writers on one root is the single corruption mode no amount of framing
    can detect after the fact, because both writers produce individually perfect
    frames. Upstream leaves this to convention. Here it is ENFORCED: interleaved
    appends are unrepresentable rather than merely unlikely.

    The guarantee has two halves, and both are needed. Across processes it is
    [Unix.lockf fd F_TLOCK 0] on [<dir>/LOCK], held open for as long as the
    handle lives. Inside one process it is a register of the roots this process
    already holds, because a POSIX advisory lock belongs to the PROCESS: a
    second handle in the same program does not contend with the first, and
    without the register a second {!acquire} here would quietly succeed.

    The register keys the CANONICAL path ([realpath] of the root), so two
    spellings of one directory — relative and absolute, a symlink and its
    target — contend like the same root, not like two different ones. *)

type t
(** A held lock. ABSTRACT, so the descriptor underneath it cannot be closed by
    anything but {!release}, and closing it is what would drop the lock. *)

type error =
  | Io of Io.error  (** The lock file could not be created or opened. *)
  | Held of { path : string }
      (** Another handle owns this root, in this process or in another one. The
          path is named so an operator can see what to look at. *)

val error_to_string : error -> string
(** A one-line rendering of an {!error}. *)

val acquire : ops:Io_ops.t -> dir:string -> (t, error) result
(** [acquire ~ops ~dir] creates [<dir>/LOCK] if it is absent and takes an
    exclusive advisory lock on it, without blocking. [dir] must already exist.

    {!Held} is a refusal, never a retry loop and never a wait: a caller that
    meets it reports it and stops. Nothing on disk is read, written or swept
    before this call returns, so a sweep can never race a live writer. *)

val release : t -> (unit, Io.error) result
(** [release t] drops the lock and closes the descriptor. The root can then be
    acquired again by this process or another one. *)
