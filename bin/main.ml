open Cohttp_eio

let authenticator =
  match Ca_certs.authenticator () with
  | Ok x -> x
  | Error (`Msg m) ->
      Fmt.failwith "Failed to create system store X509 authenticator: %s" m

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs_threaded.enable ();
  Logs.Src.set_level Cohttp_eio.src None

let https ~authenticator =
  let tls_config =
    match Tls.Config.client ~authenticator () with
    | Error (`Msg msg) -> failwith ("tls configuration problem: " ^ msg)
    | Ok tls_config -> tls_config
  in
  fun uri raw ->
    let host =
      Uri.host uri
      |> Option.map (fun x -> Domain_name.(host_exn (of_string_exn x)))
    in
    Tls_eio.client_of_flow ?host tls_config raw

let field f j = Yojson.Safe.Util.member f j |> Yojson.Safe.Util.to_string

let rec lst sw client headers prefix id =
  let resp, body =
    Client.get ~sw ~headers client
      (Uri.of_string ("https://api.box.com/2.0/folders/" ^ id ^ "/items"))
  in
  if Http.Status.compare resp.status `OK = 0 then
    let json =
      Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int
      |> Yojson.Safe.from_string
    in
    let () = Yojson.Safe.to_file "output.json" json in
    Yojson.Safe.Util.member "entries" json
    |> Yojson.Safe.Util.to_list
    |> List.iter (fun entry ->
           match field "type" entry with
           | "file" -> ()
           | "folder" -> (
               let id = field "id" entry in
               let name = field "name" entry in
               let path = prefix @ [ name ] in
               let () = Printf.printf "%s %s\n%!" id (String.concat "/" path) in
               match path with
               | [ "Data" ]
               | "Data" :: "Assets" :: _
               | "Data" :: "Assets" :: "Dunlin" :: _ ->
                   lst sw client headers path id
               | _ -> ())
           | s ->
               Printf.printf "Unknown %s\n" s;
               assert false)
  else Fmt.epr "Unexpected HTTP status: %a" Http.Status.pp resp.status

let call env token id =
  Mirage_crypto_rng_unix.use_default ();
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" ("Bearer " ^ token) in
  lst sw client headers [] id

open Cmdliner

let token =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "token" ] ~docv:"TOKEN" ~doc:"API token"

let id =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "id" ] ~docv:"ID" ~doc:"Station code to query"

let prog env =
  let doc = "Mirror Box API" in
  let info = Cmd.info "query" ~doc in
  Cmd.v info Term.(const (call env) $ token $ id)

let _ = Eio_main.run @@ fun env -> Cmd.eval (prog env)
