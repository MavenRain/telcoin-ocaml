(** Which accounts this transaction brought into existence, and which have asked
    to be removed.

    Both are facts about a transaction rather than about the world, which is why
    they live here beside the access set and the refund counter rather than on
    {!Tn_state.Account}. Neither is derivable from the state: an account created
    in this transaction is indistinguishable, by inspection, from one that has
    looked exactly like that since genesis, and an account that has run
    [SELFDESTRUCT] still has its code and its storage until the transaction ends.

    The first set is what makes EIP-6780 expressible. Since Cancun,
    [SELFDESTRUCT] deletes an account only when that account was created in the
    same transaction, and merely drains it otherwise, so the instruction has to
    ask a question about history that the account itself cannot answer. revm asks
    it of a per-account flag its journal sets in [create_account_checkpoint] and
    clears on revert ([revm-context] [journal/inner.rs:415]); this asks it of a
    set that a reverting frame drops along with the rest of its {!Effects.t}, so
    a creation that was rolled back leaves nothing behind to make a later
    [SELFDESTRUCT] delete an account it must not.

    The second set is a record, not an action. Deleting the accounts is the
    transaction layer's business and happens after the last frame returns, which
    is why an account can still be called, read and even destroyed again in the
    frames that follow. Keeping the removal out of the world state is what makes
    that faithful for free. *)

open Tn_types

type t

val empty : t
(** No account created and none destroyed: what a transaction begins with. *)

val record_creation : t -> Units.Address.t -> t
(** Note that a creation frame has just brought this address into existence. *)

val created_here : t -> Units.Address.t -> bool
(** EIP-6780's question: was this account created by this transaction? The whole
    reason the first set exists, and the only thing [SELFDESTRUCT] needs to know
    in order to choose between deleting an account and draining it. *)

val record_destruction : t -> Units.Address.t -> t
(** Note that this account has run [SELFDESTRUCT] and is to be removed when the
    transaction ends. Idempotent: an account can destroy itself twice in one
    transaction, and the second time changes nothing. *)

val destroyed : t -> Units.Address.t list
(** The accounts to remove, in address order, for the transaction layer to apply
    once execution is over. Ordered so that the list is a function of the set and
    not of the order the destructions happened in. *)

val equal : t -> t -> bool
