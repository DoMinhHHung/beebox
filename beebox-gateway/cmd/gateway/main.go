package main

import (
	"log"

	"github.com/DoMinhHHung/beebox/beebox-gateway/internal/config"
	httpx "github.com/DoMinhHHung/beebox/beebox-gateway/internal/http"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if err := httpx.Run(cfg); err != nil {
		log.Fatal(err)
	}
}
