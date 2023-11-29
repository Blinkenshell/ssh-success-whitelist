package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type login_instance struct {
	username string
	ip       string
}

func main() {
	var outputFlag = flag.String("output", "-", "Output filename or '-' for printing to stdout")
	var intervalFlag = flag.Int("interval", 1, "Interval (in minutes) in between runs")
	var debugFlag = flag.Bool("debug", false, "Run with test/debug data")
	flag.Parse()

	db, err := sql.Open("sqlite3", "./foo.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sqlStmt := `
	CREATE TABLE IF NOT EXISTS whitelist (
		username TEXT NOT NULL,
		ip TEXT NOT NULL,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (username,ip)
	);
	`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		log.Printf("%q: %s\n", err, sqlStmt)
		return
	}

	var successful_logins []login_instance
	re := regexp.MustCompile(`pam_sss\(sshd:auth\): authentication success.*rhost=([0-9.]+).*user=([a-z0-9]+)`)

	if *debugFlag == true {
		var logtext = `Nov 21 18:56:37 buildserver sshd[415552]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=194.14.45.10  user=independence
Nov 21 18:56:38 buildserver sshd[415552]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=194.14.45.10 user=independence
Nov 21 18:56:39 buildserver sshd[415552]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=194.14.45.11 user=independence
Nov 21 18:56:40 buildserver sshd[415552]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=194.14.45.10  user=bob
Nov 21 18:56:41 buildserver sshd[415552]: pam_sss(sshd:auth): authentication success; logname= uid=0 euid=0 tty=ssh ruser= rhost=194.14.45.11 user=alice`

		scanner := bufio.NewScanner(strings.NewReader(logtext))
		for scanner.Scan() {
			//fmt.Println(scanner.Text())
			var match = re.FindSubmatch([]byte(scanner.Text()))
			if len(match) == 3 {
				fmt.Printf("%s %s\n", match[1], match[2])
				successful_logins = append(successful_logins, login_instance{string(match[2]), string(match[1])})
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("error occurred: %v\n", err)
		}
	} else {
		var intervalString = fmt.Sprintf("%dmin ago", *intervalFlag)
		cmd := exec.Command("journalctl", "-t", "sshd", "-q", "--since", intervalString, "-p", "5..6", "--facility=10")
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("could not run command: ", err)
		}

		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			//fmt.Println(scanner.Text())
			var match = re.FindSubmatch([]byte(scanner.Text()))
			if len(match) == 3 {
				fmt.Printf("%q %q\n", match[1], match[2])
				successful_logins = append(successful_logins, login_instance{string(match[2]), string(match[1])})
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("error occurred: %v\n", err)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err := tx.Prepare("INSERT INTO whitelist(username, ip) VALUES(?, ?) ON CONFLICT(username, ip) DO UPDATE SET timestamp=CURRENT_TIMESTAMP")
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()
	for _, successful_login := range successful_logins {
		_, err = stmt.Exec(successful_login.username, successful_login.ip)
	}

	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}

	var output string
	rows, err := db.Query("SELECT username,ip,timestamp FROM whitelist WHERE timestamp > DATETIME('now', '-30 day')")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var username string
		var ip string
		var timestamp time.Time
		err = rows.Scan(&username, &ip, &timestamp)
		if err != nil {
			log.Fatal(err)
		}
		output += fmt.Sprintf("+:%s:%s\n", username, ip)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}

	if *outputFlag == "-" {
		fmt.Print(output)
	} else {
		os.WriteFile(*outputFlag, []byte(output), 0644)
	}
}
