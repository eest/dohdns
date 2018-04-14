package dohdns_test

import (
	"github.com/eest/dohdns"
	"log"
	"net/http"
	"os"
)

func ExampleHandleRequest() {
	certFile := "server.crt"
	keyFile := "server.key"

	logger := log.New(os.Stdout, "", 0)
	database, err := dohdns.NewProxy(nil, "", "")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", dohdns.HandleRequest(database, logger))

	log.Fatal(http.ListenAndServeTLS(":443", certFile, keyFile, nil))
}
