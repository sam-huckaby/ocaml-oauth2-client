open Lwt.Infix

type flow_type =
  | AuthorizationCode
  | ClientCredentials
  | DeviceCode

type authorization_code_config = {
  client_id: string;
  client_secret: string;
  redirect_uri: Uri.t;
  authorization_endpoint: Uri.t;
  token_endpoint: Uri.t;
  scope: string list;
}

type client_credentials_config = {
  client_id: string;
  client_secret: string;
  token_endpoint: Uri.t;
  scope: string list;
}

type device_code_config = {
  client_id: string;
  device_authorization_endpoint: Uri.t;
  token_endpoint: Uri.t;
  scope: string list;
}

type config =
  | AuthorizationCodeConfig of authorization_code_config
  | ClientCredentialsConfig of client_credentials_config
  | DeviceCodeConfig of device_code_config

type token_response = {
  access_token: string;
  token_type: string;
  expires_in: int option;
  refresh_token: string option;
  scope: string list option;
} [@@deriving yojson]

type device_code_response = {
  device_code: string;
  user_code: string;
  verification_uri: Uri.t;
  verification_uri_complete: Uri.t option;
  expires_in: int;
  interval: int;
} [@@deriving yojson]

type t = {
  flow_type: flow_type;
  config: config;
}

let create flow_type config = { flow_type; config }

let get_authorization_url t =
  match t.config with
  | AuthorizationCodeConfig config ->
    let params = [
      ("response_type", "code");
      ("client_id", config.client_id);
      ("redirect_uri", Uri.to_string config.redirect_uri);
      ("scope", String.concat " " config.scope);
    ] in
    Uri.add_query_params' config.authorization_endpoint params
  | _ -> failwith "Authorization URL only available for Authorization Code flow"

let exchange_code_for_token t code =
  match t.config with
  | AuthorizationCodeConfig config ->
    let body = [
      ("grant_type", "authorization_code");
      ("code", code);
      ("client_id", config.client_id);
      ("client_secret", config.client_secret);
      ("redirect_uri", Uri.to_string config.redirect_uri);
    ] in
    let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
    Cohttp_lwt_unix.Client.post_form ~headers config.token_endpoint body
    >>= fun (resp, body) ->
    Cohttp_lwt.Body.to_string body
    >>= fun body_str ->
    match token_response_of_yojson (Yojson.Safe.from_string body_str) with
    | Ok token -> Lwt.return token
    | Error e -> Lwt.fail_with e
  | _ -> failwith "Code exchange only available for Authorization Code flow"

let get_client_credentials_token t =
  match t.config with
  | ClientCredentialsConfig config ->
    let body = [
      ("grant_type", "client_credentials");
      ("client_id", config.client_id);
      ("client_secret", config.client_secret);
      ("scope", String.concat " " config.scope);
    ] in
    let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
    Cohttp_lwt_unix.Client.post_form ~headers config.token_endpoint body
    >>= fun (resp, body) ->
    Cohttp_lwt.Body.to_string body
    >>= fun body_str ->
    match token_response_of_yojson (Yojson.Safe.from_string body_str) with
    | Ok token -> Lwt.return token
    | Error e -> Lwt.fail_with e
  | _ -> failwith "Client credentials token only available for Client Credentials flow"

let get_device_code t =
  match t.config with
  | DeviceCodeConfig config ->
    let body = [
      ("client_id", config.client_id);
      ("scope", String.concat " " config.scope);
    ] in
    let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
    Cohttp_lwt_unix.Client.post_form ~headers config.device_authorization_endpoint body
    >>= fun (resp, body) ->
    Cohttp_lwt.Body.to_string body
    >>= fun body_str ->
    match device_code_response_of_yojson (Yojson.Safe.from_string body_str) with
    | Ok device_code -> Lwt.return device_code
    | Error e -> Lwt.fail_with e
  | _ -> failwith "Device code only available for Device Code flow"

let poll_for_device_token t device_code =
  match t.config with
  | DeviceCodeConfig config ->
    let rec poll () =
      let body = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        ("device_code", device_code.device_code);
        ("client_id", config.client_id);
      ] in
      let headers = Cohttp.Header.init_with "Content-Type" "application/x-www-form-urlencoded" in
      Cohttp_lwt_unix.Client.post_form ~headers config.token_endpoint body
      >>= fun (resp, body) ->
      Cohttp_lwt.Body.to_string body
      >>= fun body_str ->
      match token_response_of_yojson (Yojson.Safe.from_string body_str) with
      | Ok token -> Lwt.return token
      | Error _ ->
        Lwt_unix.sleep (float_of_int device_code.interval)
        >>= fun () ->
        poll ()
    in
    poll ()
  | _ -> failwith "Device token polling only available for Device Code flow" 