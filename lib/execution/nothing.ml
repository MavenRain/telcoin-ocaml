type t = |

(* The single match clause is a refutation: the compiler checks that no value of
   [t] can reach it, so the [.] body is never evaluated and the result type is
   free to be any ['a]. *)
let absurd (x : t) = match x with _ -> .
