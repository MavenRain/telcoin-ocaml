(lang dune 3.24)

(name telcoin_ocaml)

(generate_opam_files true)

(license "MIT OR Apache-2.0")

(authors "Onyeka (Oni/MavenRain) Obi")

(maintainers "Onyeka (Oni/MavenRain) Obi")

(package
 (name telcoin_ocaml)
 (synopsis "OCaml port of telcoin-network: Narwhal/Bullshark consensus with an EVM execution layer")
 (description
  "A standalone OCaml implementation of the Telcoin Network protocol: a Narwhal mempool and Bullshark DAG-consensus layer over an Ethereum-compatible execution layer.")
 (depends
  (ocaml
   (>= 5.3.0))
  (dune
   (>= 3.24))
  zarith
  (digestif
   (>= 1.1.0))
  eio
  (alcotest :with-test)
  (qcheck :with-test)))
