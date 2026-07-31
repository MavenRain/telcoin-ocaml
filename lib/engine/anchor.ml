type t = {
  hash : Tn_keccak.t;
  number : Block_number.t;
  base_fee : Tn_state.U256.t;
  gas_limit : int;
  header : Tn_evm.Block_header.t option;
}

let of_genesis ~hash ~base_fee ~gas_limit =
  { hash; number = Block_number.genesis; base_fee; gas_limit; header = None }

let of_header header =
  {
    hash = Tn_evm.Block_header.hash header;
    number = Block_number.of_int (Tn_evm.Block_header.number header);
    base_fee = Tn_evm.Block_header.base_fee_per_gas header;
    gas_limit = Tn_evm.Block_header.gas_limit header;
    header = Some header;
  }

let hash t = t.hash
let number t = t.number
let base_fee t = t.base_fee
let gas_limit t = t.gas_limit
let header t = t.header
