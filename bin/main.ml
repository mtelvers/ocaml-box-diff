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
  Logs.Src.set_level Cohttp_eio.src (Some Debug)
(* (Some Debug) *)

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

let random_string len =
  let res = Bytes.create len in
  for i = 0 to len - 1 do
    let code = Random.int (10 + 26 + 26) in
    if code < 10 then Bytes.set res i (Char.chr (Char.code '0' + code))
    else if code < 10 + 16 then
      Bytes.set res i (Char.chr (Char.code 'a' + code - 10))
    else Bytes.set res i (Char.chr (Char.code 'A' + code - (10 + 26)))
  done;
  Bytes.unsafe_to_string res

let stream_of_string x =
  let once = ref false in
  let go () =
    if !once then None
    else (
      once := true;
      Some (x, 0, String.length x))
  in
  go

let stream_of_file ~sw env filename ctx =
  let ( / ) = Eio.Path.( / ) in
  let path = Eio.Stdenv.cwd env / filename in
  let buffer = Cstruct.create 4096 in
  let flow = Eio.Path.open_in ~sw path in
  let go () =
    match Eio.Flow.single_read flow buffer with
    | 0 ->
        Eio.Flow.close flow;
        None
    | n ->
        let chunk = Cstruct.to_string (Cstruct.sub buffer 0 n) in
        let () = Sha1.update_string ctx chunk in
        Some (chunk, 0, n)
    | exception End_of_file -> None
  in
  go

let string_of_stream s =
  let buf = Buffer.create 0x100 in
  let rec go () =
    match s () with
    | None -> Buffer.contents buf
    | Some (str, off, len) ->
        Buffer.add_substring buf str off len;
        go ()
  in
  go ()

let box_upload_file env token_file id filename =
  let open Multipart_form in
  let token = read_from_file token_file |> String.trim in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let json_string =
    Yojson.Safe.to_string
      (`Assoc
         [
           ("name", `String filename);
           ("parent", `Assoc [ ("id", `String (string_of_int id)) ]);
         ])
  in
  let p0 =
    part
      ~disposition:(Content_disposition.v "attributes")
      (stream_of_string json_string)
  in
  let v =
    Content_type.make `Application (`Iana_token "octet-stream")
      Content_type.Parameters.empty
  in
  let ctx = Sha1.init () in
  let p1 =
    part
      ~disposition:(Content_disposition.v ~filename "file")
      ~header:
        (Header.of_list [ Field (Field_name.content_type, Content_type, v) ])
      (stream_of_file ~sw env filename ctx)
  in
  let t = multipart ~rng:(fun ?g:_ len -> random_string len) [ p0; p1 ] in
  let formheader, stream = to_stream t in
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" ("Bearer " ^ token) in
  let headers =
    Http.Header.add headers "content-type"
      (Header.content_type formheader |> Content_type.to_string)
  in
  let uri = "https://upload.box.com/api/2.0/files/content" in
  let resp, body =
    Client.post
      ~body:(Body.of_string (string_of_stream stream))
      ~sw ~headers client (Uri.of_string uri)
  in
  let sha1 = Sha1.finalize ctx |> Sha1.to_hex in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let () = Eio.traceln "%s" sha1 in
    let entries =
      Yojson.Safe.from_string reply
      |> Yojson.Safe.Util.member "entries"
      |> Yojson.Safe.Util.to_list
    in
    let _ =
      List.map
        (fun entry ->
          let box_sha1 =
            Yojson.Safe.Util.member "file_version" entry
            |> Yojson.Safe.Util.member "sha1"
            |> Yojson.Safe.Util.to_string
          in
          assert (sha1 = box_sha1))
        entries
    in
    Ok (Printf.printf "%s\n%!" reply)
  else (
    Fmt.epr "Unexpected HTTP status: %a" Http.Status.pp resp.status;
    Error resp.status)

let box_create_upload_session env token_file id filename =
  let token = read_from_file token_file |> String.trim in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let json_string =
    Yojson.Safe.to_string
      (`Assoc
         [
           ("folder_id", `String (string_of_int id));
           ("file_size", `Int 60_000_000);
           ("file_name", `String filename);
         ])
  in
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" ("Bearer " ^ token) in
  let headers = Http.Header.add headers "content-type" "application/json" in
  let uri = "https://upload.box.com/api/2.0/files/upload_sessions" in
  let resp, body =
    Client.post
      ~body:(Body.of_string json_string)
      ~sw ~headers client (Uri.of_string uri)
  in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let reply = Yojson.Safe.from_string reply in
    let part_size =
      Yojson.Safe.Util.member "part_size" reply |> Yojson.Safe.Util.to_int
    in
    let endpoints = Yojson.Safe.Util.member "session_endpoints" reply in
    let upload_part =
      Yojson.Safe.Util.member "upload_part" endpoints
      |> Yojson.Safe.Util.to_string
    in
    let commit =
      Yojson.Safe.Util.member "commit" endpoints |> Yojson.Safe.Util.to_string
    in
    Ok (Printf.printf "%i\n%s\n%s\n%!" part_size upload_part commit)
  else (
    Fmt.epr "Unexpected HTTP status: %a" Http.Status.pp resp.status;
    Error resp.status)

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
  (* let _ = box_upload_file env token_file 0 "stakeholder.pdf" in *)
  let _ = box_create_upload_session env token_file 0 "stakeholder.pdf" in
  (* let _ = scan env token_file src dst fldr in *)
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
