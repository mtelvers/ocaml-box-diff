# Box Diff Tool

Firstly, go to [https://app.box.com/developers/console](https://app.box.com/developers/console)
and create a new app. The use the _Generate developer token_ to create
a shortlived token to perform the check. Save the token to a file and
run the comparison.

Then to recursively compare directory `x` in both the local file system
`/a/b/c/x` and on Box in `d/e/x` run:

```sh
echo APITOKEN > token
dune exec -- ocaml-box --token-file token --src-dir /a/b/c --dest-dir d/e --dir x
```
