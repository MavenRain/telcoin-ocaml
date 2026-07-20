(** One emitted log and the shape of its topics. *)

module Topics : sig
  type word = Tn_state.U256.t

  type t =
    | T0
    | T1 of word
    | T2 of word * word
    | T3 of word * word * word
    | T4 of word * word * word * word
        (** Zero to four topics, in index order: [T2 (topic0, topic1)].

            "At most four" is not checked here, it is unwritable: there is no
            fifth constructor, so a five-topic log is not rejected, it has no
            value to be. Note this is a sum of {e tuples} and not a list beside
            a bounded count, which is the shape that would let the count and the
            payload disagree. The arity is recovered from the shape by {!arity}
            and is never stored alongside it. *)

  val arity : t -> Topic_count.t
  (** A five-arm exhaustive match. The bridge back to the decoder's operand; a
      test asserts the round trip over {!Topic_count.all}, which is the only
      place the two five-way sums could drift apart. *)

  val collect :
    Topic_count.t -> pop:('s -> (word * 's, 'e) result) -> 's -> (t * 's, 'e) result
  (** Take exactly {!Topic_count.to_int} topics from a source and build the
      matching value, first pop first, which is topic order.

      This is why {!Topic_count.t} is a type. One value simultaneously
      determines the byte encoded, the number of words popped, the constructor
      built and, through {!Gas.log_dynamic_cost}, the price charged. A [LOG3]
      that pops two topics, or prices four, is not an implementation that
      exists.

      Polymorphic in the source and in its error so that this module does not
      depend on {!Stack}: the interpreter passes a [pop] that fails with
      [Stack_underflow], and that error travels out unchanged. This function
      introduces no failure of its own. *)

  val to_list : t -> word list
  (** Index order, [topic0] first. There is deliberately no inverse: a
      projection out is safe, it is the way in that must be bounded. *)

  val equal : t -> t -> bool
end

type t

val make : address:Tn_types.Units.Address.t -> topics:Topics.t -> data:string -> t
(** [address] must be the account whose code is running, never the caller and
    never the transaction origin: revm reads [input.target_address()].

    That is an obligation on the caller and not a fact the type enforces, since
    [address] is an unconstrained argument. The interpreter's [LOG] body is the
    sole caller and takes it from the existing [executing] helper, so there is
    one site to change when [DELEGATECALL] arrives and one test ("a log names
    the executing account") standing behind it.

    [data] is a plain [string], not a {!Data.t}. {!Data.t}'s contract is
    zero-extension past its end, which is a reader's semantics; a log payload is
    a finite byte string that nothing inside the machine reads back.
    {!Interpreter}'s [Returned] output is a [string] for the same reason. *)

val address : t -> Tn_types.Units.Address.t
val topics : t -> Topics.t
val data : t -> string
val equal : t -> t -> bool

val to_string : t -> string
(** For test printers: the address, the topic count, and the hex of each topic
    and of the data. *)
