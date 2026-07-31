type t = {
  header : Tn_evm.Block_header.t;
  number : Block_number.t;
  pre_block : Tn_evm.Block_execution.Pre_block.t;
  transactions : Tn_evm.Tx_envelope.t list;
  receipts : (int * Tn_evm.Receipt.t) list;
  skipped : Tn_evm.Block_execution.Invalid_tx.t list;
  world : Tn_state.World_state.t;
  close_disposition : Tn_evm.Epoch_close.disposition option;
}

let make ~header ~number ~pre_block ~transactions ~receipts ~skipped ~world
    ~close_disposition =
  {
    header;
    number;
    pre_block;
    transactions;
    receipts;
    skipped;
    world;
    close_disposition;
  }

let header t = t.header
let number t = t.number
let pre_block t = t.pre_block
let transactions t = t.transactions
let receipts t = t.receipts
let skipped t = t.skipped
let world t = t.world
let close_disposition t = t.close_disposition
let hash t = Tn_evm.Block_header.hash t.header
