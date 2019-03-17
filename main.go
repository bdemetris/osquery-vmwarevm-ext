package main

import (
	"log"
	"os"

	osquery "github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf(`Usage: %s SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("vmwarevm", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a Generate function.
	server.RegisterPlugin(table.NewPlugin("vmwarevm", VMwareVMColums(), VMwareVMGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
