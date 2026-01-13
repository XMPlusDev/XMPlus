package main

import (
	log "github.com/sirupsen/logrus"

	"github.com/XMPlusDev/XMPlus/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
