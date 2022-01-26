/*

This scanner currently only operates on a single host, not a range of hosts, however
I will attempt to add this functionality at a later point. The extent of concurrent
connections is determined by the user, but defaults to 10. You may need to raise the
limit on the number of open files / connections if using MacOS or Linux with the
ulimit -n [max#] command if you wish to push the number of workers past a few hundred.

It also attemps to unintelligently grab a banner by taking the first 1024 bytes of a
connection. I may add attempts to try some protocol-specific requests against open
ports to enumerate additional details.

*/

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//Port is just a structure for basic port details
type Port struct {
	PortNum uint16
	Open    bool
	Banner  string
}

func main() {

	hostPtr := flag.String("host", "", "Host to scan")
	startPort := flag.Uint("start", 0, "Starting port")
	endPort := flag.Uint("stop", 0, "Final port to scan")
	workers := flag.Uint("workers", 10, "Number of concurrent workers")
	timeOut := flag.Duration("timeout", 10*time.Second, "Timeout for connections in seconds.")
	randomize := flag.Bool("random", false, "Randomize port order")
	outputFile := flag.String("outputFile", "results.txt", "File to dump results")
	openOnly := flag.Bool("openOnly", false, "Only print open ports.")

	flag.Parse()

	LimitCheck(*workers)

	if *hostPtr == "" || *startPort == 0 || *endPort == 0 {
		log.Fatal("Host, starting port, and end port cannot be blank.")
	} else if *startPort <= 0 || *endPort > 65535 {
		log.Fatal("Invalid port range.")
	}

	sem := make(chan struct{}, *workers)
	resultsChan := make(chan Port)
	wg := &sync.WaitGroup{}

	ports := portRange(*startPort, *endPort, *randomize)

	openPorts := CreateWorkers(ports, *hostPtr, *timeOut, wg, resultsChan, sem)

	close(sem)
	close(resultsChan)

	ParseResults(openPorts, *outputFile, *openOnly)

}

func portRange(start, stop uint, randomize bool) []uint16 {

	portList := []uint16{}

	for i := start; i <= stop; i++ {
		portList = append(portList, uint16(i))
	}

	if randomize == true {
		rand.Shuffle(len(portList), func(i, j int) {
			portList[i], portList[j] = portList[j], portList[i]
		})
	}

	return portList

}

func portOpen(host string, port uint16, timeout time.Duration, wg *sync.WaitGroup, resultsChan chan<- Port, sem chan struct{}) {
	defer wg.Done()

	var buf bytes.Buffer
	banner := ""

	tgt := host + ":" + strconv.FormatUint(uint64(port), 10)
	conn, err := net.DialTimeout("tcp", tgt, timeout)

	if err != nil {
		if err, _ := err.(net.Error); err.Timeout() {
			banner = "Timed Out"
		}
		resultsChan <- Port{PortNum: port, Open: false, Banner: banner}
	} else {
		defer conn.Close()
		fmt.Printf("[i] Found open port: %d\n", port)
		conn.SetDeadline(time.Now().Add(timeout))
		connData := io.LimitReader(conn, 1024)
		io.Copy(&buf, connData)
		banner = strings.TrimSpace(buf.String())
		conn.Close()
		resultsChan <- Port{PortNum: port, Open: true, Banner: banner}
	}
	<-sem
}

//CreateWorkers does what it says, creating up to the maximum amount of workers
//The sem channel blocks execution once it fills up with the max workers, waiting
//to empty a bit before continuing on.
func CreateWorkers(ports []uint16, host string, timeOut time.Duration, wg *sync.WaitGroup, resultsChan chan Port, sem chan struct{}) []Port {
	openPorts := []Port{}

	for i := 0; i < len(ports); i++ {
		sem <- struct{}{}
		wg.Add(1)
		go portOpen(host, ports[i], timeOut, wg, resultsChan, sem)
		go func() {
			result := <-resultsChan
			openPorts = append(openPorts, result)
		}()
	}

	wg.Wait()
	return openPorts
}

//ParseResults takes the slice of open ports, iterating through and formatting them
//line by line before writing to a target file. At some point will add the ability
//to export to different file formats (JSON, XML, plaintext, etc)
func ParseResults(openPorts []Port, filename string, openOnly bool) {

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].PortNum < openPorts[j].PortNum
	})

	for _, result := range openPorts {
		status := ""
		if result.Open == true {
			status = "open"
		} else {
			if openOnly == true {
				continue
			}
			status = "closed"
		}
		var port string
		port = strconv.Itoa(int(result.PortNum))
		resultLine := ""
		if len(port) < 3 {
			resultLine = "Port:" + port + "\t\tStatus:" + status + "\tBanner:" + result.Banner + "\n"
		} else {
			resultLine = "Port:" + port + "\tStatus:" + status + "\tBanner:" + result.Banner + "\n"
		}
		f.WriteString(resultLine)
	}
}

// LimitCheck compares your worker count to the maximum number of open "files" or
// connections if running Linux or MacOS. If greater than 90% capaicty, exits.
// Windows does not have the exact same form of limitation, so SUGGGESTS a lower
// thread count if over 2048.
func LimitCheck(workers uint) {
	operatingSystem := runtime.GOOS
	if operatingSystem == "linux" || operatingSystem == "darwin" {
		cmd := exec.Command("ulimit", "-n")
		out := bytes.Buffer{}
		cmd.Stdout = &out
		cmd.Run()
		maxFiles, _ := strconv.Atoi(strings.TrimSpace(out.String()))
		if float32(workers)/float32(maxFiles) >= 0.9 {
			errorMessage, _ := fmt.Printf("[!!] Number of requested workers (%d) greater than 90%% of system's maximum open files / connections (%d).\nPlease lower worker count.\n", workers, maxFiles)
			log.Println(errorMessage)
			os.Exit(0)
		} else if workers > 4096 {
			fmt.Println("[i] Try lowering your worker count below 4096 if you experience inconsistent results or unexpected behavior.")
		}
	} else if operatingSystem == "windows" {
		if workers > 2048 {
			fmt.Println("[i] Try lowering your worker count below 2048 if you experience inconsistent results or unexpected behavior..")
		} else {
			fmt.Println("[i] If you notice inconsistent results, try lowering your worker count")
		}
	}
}
