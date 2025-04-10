open Lwt.Infix
open Oauth2_client

let () =
  let config = AuthorizationCodeConfig {
    client_id = "XuJwgygdFZDOZju94n-JTNhS";  (* Replace with your client ID *)
    client_secret = "iLDUFu7mt4qWt-jqrcfUITQfkYzgCj2uXsrQYQrZODVWwUx2";  (* Replace with your client secret *)
    redirect_uri = Uri.of_string "https://www.oauth.com/playground/authorization-code.html";  (* Replace with your redirect URI *)
    authorization_endpoint = Uri.of_string "https://authorization-server.com/authorize";
    token_endpoint = Uri.of_string "https://authorization-server.com/token";  (* Replace with your token endpoint *)
    scope = ["openid"; "profile"];  (* Replace with your desired scopes *)
  } in

  let client = create AuthorizationCode config in
  
  (* Print the authorization URL *)
  let (auth_url, state) = get_authorization_url client in
  Printf.printf "Please visit this URL to authorize:\n%s\n" (Uri.to_string auth_url);
  (* Store the state value for later verification *)
  
  (* Prompt for the authorization code *)
  print_string "Enter the authorization code from the redirect URL: ";
  let code = read_line () in
  
  (* Exchange the code for a token *)
  Lwt_main.run begin
    exchange_code_for_token client code
    >>= fun token ->
    Printf.printf "Access Token: %s\n" token.access_token;
    (match token.refresh_token with
     | Some refresh_token -> Printf.printf "Refresh Token: %s\n" refresh_token
     | None -> ());
    Lwt.return_unit
  end
