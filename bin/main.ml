open Lwt.Infix
open Oauth2_client

let () =
  let config = AuthorizationCodeConfig {
    client_id = "ftsRizWRr1OIGMTjlGe8WV1W";  (* Replace with your client ID *)
    client_secret = "GBEFoyBD-aDw8mUfX-zivam0ToPO4hdf1LO-AcyG8OaNTz4c";  (* Replace with your client secret *)
    redirect_uri = Uri.of_string "https://f7be-2600-6c4a-5e7f-a177-dcea-287e-d2b-c38d.ngrok-free.app/callback";  (* Replace with your redirect URI *)
    authorization_endpoint = Uri.of_string "https://auth-us.beyondidentity.com/v1/tenants/0001c0e3613aae24/realms/420d923e7b57fe4f/applications/d85fd6a8-86a1-4058-a547-b047b9c47227/authorize";
    token_endpoint = Uri.of_string "https://auth-us.beyondidentity.com/v1/tenants/0001c0e3613aae24/realms/420d923e7b57fe4f/applications/d85fd6a8-86a1-4058-a547-b047b9c47227/token";  (* Replace with your token endpoint *)
    scope = ["openid"; "projects:read"; "projects:create"; "projects:update"; "projects:delete"];  (* Replace with your desired scopes *)
  } in

  let client = create AuthorizationCode config in
  
  (* Print the authorization URL *)
  let (auth_url, _) = get_authorization_url client in
  (* The state value needs to be stashed somewhere so that it can be access when the callback is reached *)
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
