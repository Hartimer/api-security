Companion repository for the blog post article **Securing your API - The 5 levels of "it wasn't me"**.

The code comes with tests which exemplify the interaction with the server.
```bash
$ go test -v ./...
```

You can also run the server.
```bash
$ PORT=8080 go run main.go
```

The server handler methods include sample terminal calls to test them, and so does the blog post mentioned above. An example is:
```bash
$ export CONTENT="secret"
$ export API_KEY="MY_KEY"
$ export CONTENT_HMAC=$(echo -n "$CONTENT" | hmac256 $API_KEY)
$ echo -n "$CONTENT" | curl -sSL -XPOST -H "X-API-Key: $API_KEY" -H "X-HMAC: $CONTENT_HMAC" -d @- localhost:8080/v1/tamperproof
{"content":"verified"}
```