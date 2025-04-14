open Cohttp_eio

let ( / ) = Filename.concat

let authenticator =
  match Ca_certs.authenticator () with
  | Ok x -> x
  | Error (`Msg m) -> Fmt.failwith "Failed to create system store X509 authenticator: %s" m

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
    let host = Uri.host uri |> Option.map (fun x -> Domain_name.(host_exn (of_string_exn x))) in
    Tls_eio.client_of_flow ?host tls_config raw

module Entries = Map.Make (String)

let read_from_file filename = In_channel.with_open_text filename @@ fun ic -> In_channel.input_all ic
let append_to_file filename str = Out_channel.with_open_gen [ Open_text; Open_append; Open_creat ] 0o644 filename @@ fun oc -> Out_channel.output_string oc str
let log_to_file prefix str = append_to_file "log.txt" (prefix ^ ":" ^ str ^ "\n")

let random_string len =
  let res = Bytes.create len in
  for i = 0 to len - 1 do
    let code = Random.int (10 + 26 + 26) in
    if code < 10 then Bytes.set res i (Char.chr (Char.code '0' + code))
    else if code < 10 + 16 then Bytes.set res i (Char.chr (Char.code 'a' + code - 10))
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

let stream_of_file ~sw ?(size = 4096) env filename ctx =
  let ( / ) = Eio.Path.( / ) in
  let path = Eio.Stdenv.fs env / filename in
  let buffer = Cstruct.create size in
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

let box_upload_file env token_file id path filename =
  let open Multipart_form in
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let json_string = Yojson.Safe.to_string (`Assoc [ ("name", `String filename); ("parent", `Assoc [ ("id", `String (string_of_int id)) ]) ]) in
  let p0 = part ~disposition:(Content_disposition.v "attributes") (stream_of_string json_string) in
  let v = Content_type.make `Application (`Iana_token "octet-stream") Content_type.Parameters.empty in
  let ctx = Sha1.init () in
  let p1 =
    part ~disposition:(Content_disposition.v ~filename "file")
      ~header:(Header.of_list [ Field (Field_name.content_type, Content_type, v) ])
      (stream_of_file ~sw env (path / filename) ctx)
  in
  let t = multipart ~rng:(fun ?g:_ len -> random_string len) [ p0; p1 ] in
  let formheader, stream = to_stream t in
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let headers = Http.Header.add headers "content-type" (Header.content_type formheader |> Content_type.to_string) in
  let uri = "https://upload.box.com/api/2.0/files/content" in
  let resp, body = Client.post ~body:(Body.of_string (string_of_stream stream)) ~sw ~headers client (Uri.of_string uri) in
  let sha1 = Sha1.finalize ctx |> Sha1.to_hex in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let entries = Yojson.Safe.from_string reply |> Yojson.Safe.Util.member "entries" |> Yojson.Safe.Util.to_list in
    let _ =
      List.map
        (fun entry ->
          let box_sha1 = Yojson.Safe.Util.member "file_version" entry |> Yojson.Safe.Util.member "sha1" |> Yojson.Safe.Util.to_string in
          assert (sha1 = box_sha1))
        entries
    in
    Ok (Printf.printf "%s\n%!" reply)
  else (
    Fmt.epr "Upload file %s returned unexpected HTTP status: %a" filename Http.Status.pp resp.status;
    Error resp.status)

type part = {
  offset : int;
  part_id : string;
  sha1 : string;
  size : int;
}

type session = {
  size : int;
  upload_part : Uri.t;
  commit : Uri.t;
  index : int;
  next : unit -> (string * int * int) option;
  ctx : Sha1.ctx;
  part_list : part list;
}

let box_create_upload_session sw2 env token_file id src filename size =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let json_string = Yojson.Safe.to_string (`Assoc [ ("folder_id", `String (string_of_int id)); ("file_size", `Int size); ("file_name", `String filename) ]) in
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let headers = Http.Header.add headers "content-type" "application/json" in
  let uri = "https://upload.box.com/api/2.0/files/upload_sessions" in
  let resp, body = Client.post ~body:(Body.of_string json_string) ~sw ~headers client (Uri.of_string uri) in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let reply = Yojson.Safe.from_string reply in
    let part_size = Yojson.Safe.Util.member "part_size" reply |> Yojson.Safe.Util.to_int in
    let endpoints = Yojson.Safe.Util.member "session_endpoints" reply in
    let upload_part = Yojson.Safe.Util.member "upload_part" endpoints |> Yojson.Safe.Util.to_string in
    let commit = Yojson.Safe.Util.member "commit" endpoints |> Yojson.Safe.Util.to_string in
    let () = Printf.printf "%i\n%s\n%s\n%!" part_size upload_part commit in
    let ctx = Sha1.init () in
    Ok
      {
        size;
        upload_part = Uri.of_string upload_part;
        commit = Uri.of_string commit;
        next = stream_of_file ~sw:sw2 ~size:part_size env (src / filename) ctx;
        index = 0;
        ctx;
        part_list = [];
      }
  else (
    Fmt.epr "Create upload session for %s returned unexpected HTTP status: %a" filename Http.Status.pp resp.status;
    Error resp.status)

let box_list_folder env token_file id marker =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let uri = "https://api.box.com/2.0/folders/" ^ string_of_int id ^ "/items?usemarker=true&limit=1000" in
  let uri =
    match marker with
    | Some m -> uri ^ "&marker=" ^ m
    | None -> uri
  in
  let resp, body = Client.get ~sw ~headers client (Uri.of_string uri) in
  if Http.Status.compare resp.status `OK = 0 then
    let json = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int |> Yojson.Safe.from_string in
    let next_marker = Yojson.Safe.Util.member "next_marker" json |> Yojson.Safe.Util.to_string_option in
    Ok
      ( Yojson.Safe.Util.member "entries" json |> Yojson.Safe.Util.to_list
        |> List.filter_map (fun entry ->
               match Yojson.Safe.Util.member "type" entry with
               | `String "file"
               | `String "folder" ->
                   let id = Yojson.Safe.Util.member "id" entry |> Yojson.Safe.Util.to_string |> int_of_string in
                   let name = Yojson.Safe.Util.member "name" entry |> Yojson.Safe.Util.to_string in
                   Some (name, id)
               | _ ->
                   Printf.printf "Unknown entry\n";
                   assert false)
        |> Entries.of_list,
        next_marker )
  else Error resp.status

let cache = Hashtbl.create 100000

let box_create_folder env token_file id folder =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let json_string = Yojson.Safe.to_string (`Assoc [ ("name", `String folder); ("parent", `Assoc [ ("id", `String (string_of_int id)) ]) ]) in
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let headers = Http.Header.add headers "content-type" "application/json" in
  let uri = "https://api.box.com/2.0/folders" in
  let resp, body = Client.post ~body:(Body.of_string json_string) ~sw ~headers client (Uri.of_string uri) in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let reply = Yojson.Safe.from_string reply in
    let newid = Yojson.Safe.Util.member "id" reply |> Yojson.Safe.Util.to_string in
    let map = Hashtbl.find cache id in
    let map = Entries.add folder (int_of_string newid) map in
    let () = Hashtbl.replace cache id map in
    Ok (Printf.printf "%s\n%!" newid)
  else (
    Fmt.epr "Create folder %s returned unexpected HTTP status: %a" folder Http.Status.pp resp.status;
    Error resp.status)

let box_upload_part_file env token_file session =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let headers = Http.Header.add headers "content-type" "application/octet-stream" in
  let block, _, len = session.next () |> Option.value ~default:("", 0, 0) in
  let range = Printf.sprintf "bytes %i-%i/%i" session.index (session.index + len - 1) session.size in
  let headers = Http.Header.add headers "content-range" range in
  let sha1 = Sha1.string block |> Sha1.to_bin |> Base64.encode_string |> String.cat "sha=" in
  let headers = Http.Header.add headers "digest" sha1 in
  let headers = Http.Header.add headers "Content-Length" (string_of_int len) in
  let resp, body = Client.put ~body:(Body.of_string block) ~sw ~headers client session.upload_part in
  if Http.Status.compare resp.status `OK = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let reply = Yojson.Safe.from_string reply in
    let part = Yojson.Safe.Util.member "part" reply in
    let offset = Yojson.Safe.Util.member "offset" part |> Yojson.Safe.Util.to_int in
    let part_id = Yojson.Safe.Util.member "part_id" part |> Yojson.Safe.Util.to_string in
    let sha1 = Yojson.Safe.Util.member "sha1" part |> Yojson.Safe.Util.to_string in
    let size = Yojson.Safe.Util.member "size" part |> Yojson.Safe.Util.to_int in
    Ok { session with index = session.index + len; part_list = { offset; part_id; sha1; size } :: session.part_list }
  else (
    Fmt.epr "Upload part returned unexpected HTTP status: %a" Http.Status.pp resp.status;
    Error resp.status)

let box_upload_commit env token_file session =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let headers = Http.Header.add headers "content-type" "application/json" in
  let sha1 = Sha1.finalize session.ctx |> Sha1.to_bin |> Base64.encode_string |> String.cat "sha=" in
  let headers = Http.Header.add headers "digest" sha1 in
  let json_string =
    Yojson.Safe.to_string
      (`Assoc
         [
           ( "parts",
             `List
               (List.rev_map
                  (fun part ->
                    `Assoc [ ("part_id", `String part.part_id); ("offset", `Int part.offset); ("size", `Int part.size); ("sha1", `String part.sha1) ])
                  session.part_list) );
         ])
  in
  let resp, body = Client.post ~body:(Body.of_string json_string) ~sw ~headers client session.commit in
  if Http.Status.compare resp.status `Created = 0 then
    let reply = Eio.Buf_read.(parse_exn take_all) body ~max_size:max_int in
    let reply = Yojson.Safe.from_string reply in
    let id = Yojson.Safe.Util.member "id" reply in
    Ok id
  else (
    Fmt.epr "Upload commit returned unexpected HTTP status: %a" Http.Status.pp resp.status;
    Error resp.status)

let box_delete_file env token_file id =
  let token = read_from_file token_file |> String.trim |> String.cat "Bearer " in
  let client = Client.make ~https:(Some (https ~authenticator)) env#net in
  Eio.Switch.run @@ fun sw ->
  let headers = Http.Header.init () in
  let headers = Http.Header.add headers "authorization" token in
  let uri = "https://api.box.com/2.0/files/" ^ string_of_int id in
  let resp, _ = Client.delete ~sw ~headers client (Uri.of_string uri) in
  if Http.Status.compare resp.status `No_content = 0 then Ok ()
  else (
    Fmt.epr "Delete file %i returned unexpected HTTP status: %a" id Http.Status.pp resp.status;
    Error resp.status)

let rec box_check env token_file id = function
  | [] ->
      let () = Printf.printf "OK\n%!" in
      Some id
  | hd :: tl -> (
      let entries =
        match Hashtbl.find_opt cache id with
        | Some entries -> entries
        | None ->
            let rec loop marker =
              match box_list_folder env token_file id marker with
              | Ok (map, next_marker) -> (
                  match next_marker with
                  | Some _ -> Entries.union (fun _ _ a -> Some a) map (loop next_marker)
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
          None)

let upload env token_file id src filename =
  Eio.Switch.run @@ fun sw ->
  let stat = Unix.stat (src / filename) in
  let session = box_create_upload_session sw env token_file id src filename stat.st_size |> Result.get_ok in
  let rec loop session =
    let () = Eio.traceln "%i/%i" session.index session.size in
    let session = box_upload_part_file env token_file session |> Result.get_ok in
    if session.index = session.size then session else loop session
  in
  let session = loop session in
  let _ = box_upload_commit env token_file session in
  ()

let scan env token_file src dst p =
  let rec loop = function
    | hd :: tl when Sys.is_directory (src / hd) ->
        (* does hd exist in box? *)
        let () = Printf.printf "Check box for path %s - %!" (dst / hd) in
        let v = box_check env token_file 0 (String.split_on_char '/' (dst / hd)) in
        let () =
          if Option.is_none v then
            let name = Filename.basename hd in
            let dir = Filename.dirname hd in
            let id = box_check env token_file 0 (String.split_on_char '/' (dst / dir)) in
            ignore (box_create_folder env token_file (Option.value ~default:0 id) name)
        in
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
    | hd :: tl ->
        let () = Printf.printf "Check box for file %s - %!" (dst / hd) in
        let () =
          match box_check env token_file 0 (String.split_on_char '/' (dst / hd)) with
          | Some _ -> ()
          | None ->
              let name = Filename.basename hd in
              let dir = Filename.dirname hd in
              let id = box_check env token_file 0 (String.split_on_char '/' (dst / dir)) in
              let stat = Unix.stat (src / hd) in
              if stat.st_size < 50_000_000 then
                let () = log_to_file "upload" hd in
                ignore (box_upload_file env token_file (Option.value ~default:0 id) (src / dir) name)
              else if stat.st_size < 15_000_000_000 then
                let () = log_to_file "big upload" hd in
                ignore (upload env token_file (Option.value ~default:0 id) (src / dir) name)
              else log_to_file "too big" hd
        in
        loop tl
    | [] -> []
  in
  loop [ p ]

let rec rev_scan env token_file src dst fldr path id =
  match Hashtbl.find_opt cache id with
  | None ->
      let dst = dst / fldr in
      if String.starts_with ~prefix:(dst ^ "/") path then
        let src = src / fldr / String.sub path (1 + String.length dst) (String.length path - String.length dst - 1) in
        if not (Sys.file_exists src) then
          let () = Eio.traceln "%i %s" id path in
          let () = log_to_file "delete" path in
          ignore (box_delete_file env token_file id)
  | Some map -> Entries.iter (fun s id -> rev_scan env token_file src dst fldr (path / s) id) map

let call env token_file src dst fldr =
  Mirage_crypto_rng_unix.use_default ();
  let _ = scan env token_file src dst fldr in
  let _ = rev_scan env token_file src dst fldr "" 0 in
  ()

open Cmdliner

let token_file = Arg.required @@ Arg.opt Arg.(some string) None @@ Arg.info [ "token-file" ] ~docv:"TOKEN" ~doc:"API token"
let src_dir = Arg.required @@ Arg.opt Arg.(some string) None @@ Arg.info [ "src-dir" ] ~docv:"SRC_DIR" ~doc:"Source Directory"
let dest_dir = Arg.required @@ Arg.opt Arg.(some string) None @@ Arg.info [ "dest-dir" ] ~docv:"DEST_DIR" ~doc:"Destination Directory"
let dir = Arg.required @@ Arg.opt Arg.(some string) None @@ Arg.info [ "dir" ] ~docv:"DIR" ~doc:"Directory to compare in SRC_DIR with the one in DEST_DIR"

let prog env =
  let doc = "Compare a local DIR in SRC_DIR with DEST_DIR on Box using the Box API" in
  let info = Cmd.info "box" ~doc in
  Cmd.v info Term.(const (call env) $ token_file $ src_dir $ dest_dir $ dir)

let _ = Eio_main.run @@ fun env -> Cmd.eval (prog env)
