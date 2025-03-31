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

module Entries = Map.Make (String)

let read_from_file filename =
  In_channel.with_open_text filename @@ fun ic -> In_channel.input_all ic

let box_list_folder env token_file id marker =
  let token = read_from_file token_file |> String.trim in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" ("Bearer " ^ token) in
  let uri =
    "https://api.box.com/2.0/folders/" ^ string_of_int id
    ^ "/items?usemarker=true&limit=1000"
  in
  let uri = match marker with Some m -> uri ^ "&marker=" ^ m | None -> uri in
  let resp, body = Client.get ~sw ~headers client (Uri.of_string uri) in
  if Http.Status.compare resp.status `OK = 0 then
    let json =
      Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int
      |> Yojson.Safe.from_string
    in
    let next_marker =
      Yojson.Safe.Util.member "next_marker" json
      |> Yojson.Safe.Util.to_string_option
    in
    Ok
      ( Yojson.Safe.Util.member "entries" json
        |> Yojson.Safe.Util.to_list
        |> List.filter_map (fun entry ->
               match Yojson.Safe.Util.member "type" entry with
               | `String "file" | `String "folder" ->
                   let id =
                     Yojson.Safe.Util.member "id" entry
                     |> Yojson.Safe.Util.to_string |> int_of_string
                   in
                   let name =
                     Yojson.Safe.Util.member "name" entry
                     |> Yojson.Safe.Util.to_string
                   in
                   Some (name, id)
               | _ ->
                   Printf.printf "Unknown entry\n";
                   assert false)
        |> Entries.of_list,
        next_marker )
  else Error resp.status

let cache = Hashtbl.create 100000

let rec box_check env token_file id = function
  | [] ->
      let () = Printf.printf "OK\n%!" in
      true
  | hd :: tl -> (
      let entries =
        match Hashtbl.find_opt cache id with
        | Some entries -> entries
        | None ->
            let rec loop marker =
              match box_list_folder env token_file id marker with
              | Ok (map, next_marker) -> (
                  match next_marker with
                  | Some _ ->
                      Entries.union (fun _ _ a -> Some a) map (loop next_marker)
                  | None -> map)
              | Error _ ->
                  let () = Printf.printf "sleeping\n%!" in
                  let () = Unix.sleep 60 in
                  loop marker
            in
            let map = loop None in
            let () = Hashtbl.add cache id map in
            map
      in
      match Entries.find_opt hd entries with
      | Some id -> box_check env token_file id tl
      | None ->
          let () = Printf.printf "Not found\n%!" in
          false)

let scan env token_file src dst p =
  let rec loop = function
    | hd :: tl when Sys.is_directory (src / hd) ->
        (* does hd exist in box? *)
        let () = Printf.printf "Check box for path %s - %!" (dst / hd) in
        let v =
          box_check env token_file 0 (String.split_on_char '/' (dst / hd))
        in
        if v then
          let d =
            Sys.readdir (src / hd)
            |> Array.to_list
            |> List.filter_map (fun name ->
                   match name with
                   | "Thumbs.db" -> None
                   | s when String.starts_with ~prefix:"." s -> None
                   | s when String.starts_with ~prefix:"~$" s -> None
                   | s when String.ends_with ~suffix:".tmp" s -> None
                   | s when String.ends_with ~suffix:".TMP" s -> None
                   | n -> Some (Filename.concat hd n))
          in
          loop (d @ tl)
        else loop tl
    | hd :: tl ->
        let () = Printf.printf "Check box for file %s - %!" (dst / hd) in
        let _ =
          box_check env token_file 0 (String.split_on_char '/' (dst / hd))
        in
        loop tl
    | [] -> []
  in
  loop [ p ]

let call env token_file src dst fldr =
  Mirage_crypto_rng_unix.use_default ();
  let _ = scan env token_file src dst fldr in
  ()

open Cmdliner

let token_file =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "token-file" ] ~docv:"TOKEN" ~doc:"API token"

let src_dir =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "src-dir" ] ~docv:"SRC_DIR" ~doc:"Source Directory"

let dest_dir =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "dest-dir" ] ~docv:"DEST_DIR" ~doc:"Destination Directory"

let dir =
  Arg.required
  @@ Arg.opt Arg.(some string) None
  @@ Arg.info [ "dir" ] ~docv:"DIR"
       ~doc:"Directory to compare in SRC_DIR with the one in DEST_DIR"

let prog env =
  let doc =
    "Compare a local DIR in SRC_DIR with DEST_DIR on Box using the Box API"
  in
  let info = Cmd.info "box" ~doc in
  Cmd.v info Term.(const (call env) $ token_file $ src_dir $ dest_dir $ dir)

let _ = Eio_main.run @@ fun env -> Cmd.eval (prog env)
