package main

import (
	"flag"
	"fmt"
	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func main() {
	c := &Config{}

	h := flag.Bool("h", false, "Print this help")
	d := flag.Bool("d", false, "Dump config values")
	flag.Parse()

	if *h {
		flag.Usage()
		fmt.Print("\n")
		envconfig.Usage("", c)
		return
	}

	err := envconfig.Process("", c)
	if err != nil {
		log.Fatal(err.Error())
		os.Exit(1)
	}

	if *d {
		fmt.Printf("%+v\n", c)
		return
	}

	initLog(c)

	p, err := NewLDAPAuthProxy(c)

	if err != nil {
		log.Fatal(err)
	}

	log.Info(fmt.Sprintf("Listening on %s", c.Listen))
	log.Fatal(http.ListenAndServe(c.Listen, p))
}
