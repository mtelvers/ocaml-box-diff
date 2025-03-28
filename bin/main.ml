open Cohttp_eio

let ( / ) = Filename.concat

let authenticator =
  match Ca_certs.authenticator () with
  | Ok x -> x
  | Error (`Msg m) ->
      Fmt.failwith "Failed to create system store X509 authenticator: %s" m

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs_threaded.enable ();
  Logs.Src.set_level Cohttp_eio.src None (* (Some Debug) *)

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

module Entries = Map.Make (String)

let lst env token id =
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" ("Bearer " ^ token) in
  let resp, body =
    Client.get ~sw ~headers client
      (Uri.of_string ("https://api.box.com/2.0/folders/" ^ (string_of_int id) ^ "/items"))
  in
  if Http.Status.compare resp.status `OK = 0 then
    let json =
      Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int
      |> Yojson.Safe.from_string
    in
    Yojson.Safe.Util.member "entries" json
    |> Yojson.Safe.Util.to_list
    |> List.filter_map (fun entry ->
           match field "type" entry with
           | "file" -> None
           | "folder" ->
               let id = field "id" entry |> int_of_string in
               let name = field "name" entry in
               Some (name, id)
           | s ->
               Printf.printf "Unknown %s\n" s;
               assert false)
  else
    assert false
      (* Fmt.epr "Unexpected HTTP status: %a" Http.Status.pp resp.status *)

let cache = Hashtbl.create 10000

let rec box_check env token id = function
  | [] ->
        let () = Printf.printf "OK\n%!" in true
  | hd :: tl -> (
      let entries =
        match Hashtbl.find_opt cache id with
        | Some entries -> entries
        | None ->
            let map = lst env token id |> Entries.of_list in
            let () = Hashtbl.add cache id map in
            map
      in
      match Entries.find_opt hd entries with
      | Some id -> box_check env token id tl
      | None ->
        let () = Printf.printf "Not found\n%!" in
        false)

let scan env token src dst p =
  let rec loop = function
    | hd :: tl when Sys.is_directory (src / hd) ->
        (* does hd exist in box? *)
        let () = Printf.printf "Check box for path %s - %!" (dst / hd) in
        let v = box_check env token 0 (String.split_on_char '/' (dst / hd)) in
        if v then
        Sys.readdir (src / hd) |> Array.to_list
        |> List.map (Filename.concat hd)
        |> List.append tl |> loop
        else loop tl
    (*| hd :: tl -> hd :: loop tl *)
    | _ :: tl -> loop tl
    | [] -> []
  in
  loop [ p ]

let call env token _ =
  Mirage_crypto_rng_unix.use_default ();
  let _ = scan env token "/data2/Assets" "Data/Assets" "Dunlin"
  in ()

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
