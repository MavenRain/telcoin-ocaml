(** The EVM operand stack: at most 1024 words, immutable and all-or-nothing.

    Every operation returns a new stack and never a partially modified one — an
    operation that cannot be satisfied returns [Error] and the caller keeps the
    stack it had. That matches the real machine, where a failed push or pop is an
    exceptional halt that discards the frame outright, so no observer can ever
    see a half-applied stack.

    The depth limit is checked {e before} a push, so the stack holds at most 1024
    words and a push onto a full stack fails leaving it full — not 1025 words
    briefly.

    The words are held in an immutable list, top first, so a push or a pop is
    constant time while {!swap} rebuilds the stack rather than exchanging two
    slots in place. On a deep stack that is real work for a three-gas
    instruction; it buys persistence, and no caller of this interface can tell
    the difference if a later chunk replaces the representation. Operand order follows the opcode: {!pop2} returns the word popped
    first (the top of the stack) as its first component, which is the order
    {!Alu} takes its arguments in. *)

type word = Tn_state.U256.t

type t
(** A stack of at most {!limit} words. *)

type error =
  | Underflow  (** Fewer words on the stack than the operation consumes. *)
  | Overflow  (** The push would take the stack past {!limit} words. *)

val error_to_string : error -> string

val limit : int
(** [1024] — the maximum depth, the EVM's [STACK_LIMIT]. *)

val empty : t
(** The empty stack a frame begins with. *)

val depth : t -> int
(** How many words the stack holds. *)

val push : word -> t -> (t, error) result
(** Push a word, [Error Overflow] when the stack already holds {!limit} words. *)

val pop : t -> (word * t, error) result
(** Pop the top word, [Error Underflow] when the stack is empty. *)

val pop2 : t -> (word * word * t, error) result
(** Pop two words — the first component is the word popped first. Nothing is
    popped unless both are available. *)

val pop3 : t -> (word * word * word * t, error) result
(** Pop three words, first-popped first, all or nothing. *)

val dup : Depth.t -> t -> (t, error) result
(** [dup n] pushes a copy of the [n]-th word from the top ([DUP n]).
    [Error Underflow] when the stack is shallower than [n], [Error Overflow]
    when it is already full.

    {b Divergence from revm, deliberate:} revm reports {e both} of those as
    [StackOverflow] for [DUP] and [SWAP], because the underlying stack helper
    returns a bare boolean the instruction wrapper cannot tell apart
    ([revm-interpreter] [instructions/stack.rs:44-62]). This port reports the
    condition that actually held. Nothing observable turns on it: every
    exceptional halt discards the frame, consumes the whole gas allowance and
    returns no output, so the halt {e reason} is diagnostic only — see
    {!Interpreter.error}. *)

val swap : Depth.t -> t -> (t, error) result
(** [swap n] exchanges the top word with the word [n] places below it
    ([SWAP n]), so [swap 1] exchanges the top two. [Error Underflow] unless the
    stack holds at least [n + 1] words. The depth is unchanged, so this cannot
    overflow. *)

val to_list : t -> word list
(** The words, top first. *)

val of_list : word list -> t option
(** A stack holding the given words, top first — [None] if there are more than
    {!limit} of them. For tests and for reasoning about a mid-execution state;
    execution itself only ever builds a stack from {!empty}. *)
