(lang dune 3.16)

(name ocaml_oauth2_client)

(generate_opam_files true)

(source
 (github sam-huckaby/ocaml-oauth2-client))

(authors "Sam huckaby")

(maintainers "Sam Huckaby")

(license MIT)

(documentation https://github.com/sam-huckaby/ocaml-oauth2-client)

(package
 (name ocaml_oauth2_client)
 (synopsis "A straightforward OAuth2 client")
 (description "A client library for OAuth2 that will help make the setup of secure auth flows easy to manage and straightforward to setup.")
 (depends
  ocaml
  dune
  cohttp-lwt-unix
  yojson
  uri
  ppx_deriving
  ppx_deriving_yojson)
 (tags
  (oauth2 security oauth)))

(library
 (name oauth2_client)
 (public_name oauth2_client)
 (libraries cohttp-lwt-unix yojson uri ppx_deriving ppx_deriving_yojson)
 (preprocess (pps ppx_deriving ppx_deriving_yojson)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html
