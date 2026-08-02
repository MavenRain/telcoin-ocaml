open Tn_types

type t = Units.Address.t Authority_id.Map.t

let of_committee committee =
  List.fold_left
    (fun book authority ->
      Authority_id.Map.add (Authority.id authority)
        (Authority.execution_address authority)
        book)
    Authority_id.Map.empty
    (Committee.authorities committee)

let union newer older =
  Authority_id.Map.union
    (fun _id newer_address _older_address -> Some newer_address)
    newer older

let find book id = Authority_id.Map.find_opt id book
