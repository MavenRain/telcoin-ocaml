type scope = Consensus_vote

(* Three bytes: scope, version, app-id. Telcoin consensus uses [2; 0; 1]. *)
let prefix = function Consensus_vote -> "\x02\x00\x01"
let wrap scope msg = prefix scope ^ msg
