type advance = {
  consensus : Tn_execution.Consensus_block.t;
  output : Tn_batch.Output.t;
  blocks : Tn_engine.Executed_block.t list;
  closes_epoch : bool;
}

type error =
  | Receive of Subscriber.error
  | Execute of Tn_engine.Engine.error
  | Epoch_mismatch of {
      installed : Tn_types.Units.Epoch.t;
      output : Tn_types.Units.Epoch.t;
    }
  | Sealed_needs_handoff

let error_to_string = function
  | Receive e -> Subscriber.error_to_string e
  | Execute e -> Tn_engine.Engine.error_to_string e
  | Epoch_mismatch { installed; output } ->
      Printf.sprintf
        "output refused: leader epoch %s does not match the installed \
         committee epoch %s"
        (Tn_types.Units.Epoch.to_string output)
        (Tn_types.Units.Epoch.to_string installed)
  | Sealed_needs_handoff ->
      "the driver's epoch is sealed: the epoch handoff (begin_epoch) is owed \
       before the next output"

type 'driver t =
  | Advance of { driver : 'driver; advances : advance list }
  | Sealed of {
      driver : 'driver;
      advances : advance list;
      rest : Tn_consensus.Sub_dag.t list;
    }
  | Halted of { advances : advance list; error : error }
