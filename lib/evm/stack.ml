type word = Tn_state.U256.t

(* The words with the top of the stack first, alongside the depth so that the
   limit check is O(1). The two fields are kept in step by construction: every
   function below builds the new list and its length together. *)
type t = { words : word list; depth : int }

type error = Underflow | Overflow

let error_to_string = function
  | Underflow -> "stack underflow"
  | Overflow -> "stack overflow"

let limit = 1024
let empty = { words = []; depth = 0 }
let depth t = t.depth

(* The limit is checked before the push, so the stack never exceeds it even
   transiently and a push onto a full stack leaves it exactly as it was. *)
let push w t =
  if t.depth >= limit then Error Overflow
  else Ok { words = w :: t.words; depth = t.depth + 1 }

let pop t =
  match t.words with
  | [] -> Error Underflow
  | w :: rest -> Ok (w, { words = rest; depth = t.depth - 1 })

(* Two and three pops thread the intermediate stack, so either every word is
   removed or — the [Error] case short-circuits before any state escapes —
   none is. *)
let pop2 t =
  Result.bind (pop t) (fun (a, t) ->
      Result.map (fun (b, t) -> (a, b, t)) (pop t))

let pop3 t =
  Result.bind (pop2 t) (fun (a, b, t) ->
      Result.map (fun (c, t) -> (a, b, c, t)) (pop t))

(* [DUP n] copies the [n]-th word from the top, which is index [n - 1] in a
   top-first list; a missing index is exactly the underflow case, so the lookup
   and the depth check are one and the same. *)
let dup n t =
  Option.fold ~none:(Error Underflow)
    ~some:(fun w -> push w t)
    (List.nth_opt t.words (Depth.to_int n - 1))

(* [SWAP n] exchanges index [0] with index [n]. Reaching index [n] proves the
   stack is deep enough for both, so the pair is looked up together and the
   exchange itself is a total rewrite of the list — the depth cannot change, so
   no overflow is possible. *)
let swap n t =
  let n = Depth.to_int n in
  Option.fold ~none:(Error Underflow)
    ~some:(fun (top, below) ->
      Ok
        {
          t with
          words =
            List.mapi
              (fun i w -> if i = 0 then below else if i = n then top else w)
              t.words;
        })
    (Option.bind (List.nth_opt t.words 0) (fun top ->
         Option.map (fun below -> (top, below)) (List.nth_opt t.words n)))

let to_list t = t.words

let of_list words =
  let depth = List.length words in
  if depth > limit then None else Some { words; depth }
