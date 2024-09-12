package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/akrylysov/algnhsa"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/server"
)

func main() {
	bucket := os.Getenv("LFS_BUCKET")
	if bucket == "" {
		log.Fatalln("LFS_BUCKET must be set")
	}

	s, err := server.New(server.Options{
		S3Accelerate: true,
		Bucket:       bucket,
		IsAuthorized: auth.GiteeAuth(),
	})
	if err != nil {
		log.Fatalln(err)
	}

	if strings.HasPrefix(os.Getenv("AWS_EXECUTION_ENV"), "AWS_Lambda_") {
		algnhsa.ListenAndServe(s, nil)
	} else {
		log.Println("serving on http://127.0.0.1:5000 ...")
		if err := http.ListenAndServe("127.0.0.1:5000", s); err != nil {
			log.Fatalln(err)
		}
	}
}
