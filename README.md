# SSH Tunnel Helper

Use this little helper to create SSH tunnels to remote hosts, e.g. to access a database.

- **Concurrency-safe**: `Dial` may be called from many goroutines (e.g. by a database driver's connection pool); calls are serialised internally.
- **One shared SSH transport**: a single SSH handshake is reused for all connections (one channel per `Dial`); later `Dial`s never tear down connections opened earlier.
- **Self-healing**: a dead transport (NAT drop, server restart) is detected and re-established transparently on the next `Dial`.
- **Keepalives**: SSH-level `keepalive@openssh.com` probes (default every 30s, tune with `WithKeepalive`) keep NAT/firewall state warm and detect dead paths early.

### Example
```golang
package main

import (
	"database/sql"

	"github.com/dmytro-vovk/sshtun"
	"github.com/go-sql-driver/mysql"
)

func main() {
	// Create a new SSH tunnel to the remote host
	tun := sshtun.NewWithPKPath("remote-host:22", "username", "$HOME/.ssh/id_rsa")

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
```
More examples can be found in the [examples](examples) directory.
