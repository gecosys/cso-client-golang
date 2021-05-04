A library for connecting to the Cloud Socket system.

## Introduce Cloud Socket
Connectivity is the key word for Internet of Things.

Cloud Socket is a connection platform to manage connections and data routing between clients and servers in IoT projects. The platform is robust, flexible, and scalable to accommodate large-scale connections, while securing, queuing and preventing data from being lost on network or offline destination connection.

## Usage
```golang
package main

import (
	"fmt"
	"time"

	"github.com/gecosys/cso-client-golang/config"
	"github.com/gecosys/cso-client-golang/csoconnector"
	"github.com/gecosys/cso-client-golang/csoparser"
	"github.com/gecosys/cso-client-golang/csoproxy"
	"github.com/gecosys/cso-client-golang/csoqueue"
)

func main() {
	bufferSize := int32(1024)

	// Read config from file
	conf, err := config.NewConfigFromFile("cso_key.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Init connector
	// connector := csoconnector.DefaultConnector(bufferSize, conf)
	connector := csoconnector.NewConnector(
		bufferSize,
		csoqueue.NewQueue(bufferSize),
		csoparser.NewParser(),
		csoproxy.NewProxy(conf),
		conf,
	)

	// Send a message to the connection itself every 1 second
	go loopSendMessage(conf.GetConnectionName(), connector)

	// Open a connection to the Cloud Socket system
	connector.Listen(func(sender string, data []byte) error {
		fmt.Printf("Received message from %s: ", sender)
		fmt.Println(string(data))
		return nil
	})
}

func loopSendMessage(receiver string, connector csoconnector.Connector) {
	timer := time.NewTimer(0)
	for range timer.C {
		err := connector.SendMessage(receiver, []byte("Goldeneye Ecosystem"), true, false)
		if err != nil {
			fmt.Println(err)
		}
		timer.Reset(1000 * time.Millisecond)
	}
}
```

## Website
https://cso.goldeneyetech.com.vn
