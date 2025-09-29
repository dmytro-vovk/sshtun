package main

import (
	"database/sql"
	"os"

	"github.com/dmytro-vovk/sshtun"
	"github.com/go-sql-driver/mysql"
)

func main() {
	// Read the private key from the file
	pk, err := os.ReadFile(os.ExpandEnv("$HOME/.ssh/id_rsa"))
	if err != nil {
		panic(err)
	}

	// Create a new SSH tunnel to the remote host
	tun := sshtun.NewWithPK("remote-host:22", "username", pk)

	defer tun.Close()

	// Register the new dialer with the mysql driver
	mysql.RegisterDialContext("tcp+ssh", tun.Dial)

	// Open a connection to the database
	conn, err := sql.Open("mysql", "username:password@tcp+ssh(localhost:3306)/database")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Ping the database
	if err := conn.Ping(); err != nil {
		panic(err)
	}
}
