package main

import (
	"bytes"
	//"encoding/json"
	//	"encoding/binary"
	//"errors"
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

	limitCheck(*workers)

	if *hostPtr == "" || *startPort == 0 || *endPort == 0 {
		log.Fatal("Host, starting port, and end port cannot be blank.")
	} else if *startPort <= 0 || *endPort > 65535 {
		log.Fatal("Invalid port range.")
	}

	f, err := os.Create(*outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	sem := make(chan struct{}, *workers)
	resultsChan := make(chan Port)
	openPorts := []Port{}

	wg := &sync.WaitGroup{}

	ports := portRange(*startPort, *endPort)

	if *randomize == true {
		rand.Shuffle(len(ports), func(i, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	for i := 0; i < len(ports); i++ {
		sem <- struct{}{}
		wg.Add(1)
		go portOpen(*hostPtr, ports[i], *timeOut, wg, resultsChan, sem)
		go func() {
			result := <-resultsChan
			openPorts = append(openPorts, result)
		}()

	}

	wg.Wait()

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].PortNum < openPorts[j].PortNum
	})

	for _, result := range openPorts {
		status := ""
		if result.Open == true {
			status = "open"
		} else {
			if *openOnly == true {
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

func portRange(start, stop uint) []uint16 {

	portList := []uint16{}

	for i := start; i <= stop; i++ {
		portList = append(portList, uint16(i))
	}

	return portList

}

func portOpen(host string, port uint16, timeout time.Duration, wg *sync.WaitGroup, resultsChan chan<- Port, sem chan struct{}) {
	defer wg.Done()

	result := Port{}

	t := host + ":" + strconv.FormatUint(uint64(port), 10)
	conn, err := net.DialTimeout("tcp", t, timeout)
	banner := ""
	if err != nil {
		if err, _ := err.(net.Error); err.Timeout() {
			banner = "Timed Out"
		}
		result = Port{PortNum: port, Open: false, Banner: banner}
	} else {
		defer conn.Close()
		fmt.Printf("[i] Found open port: %d\n", port)
		conn.SetDeadline(time.Now().Add(timeout))
		var buf bytes.Buffer
		thing := io.LimitReader(conn, 1024)
		io.Copy(&buf, thing)
		banner = strings.TrimSpace(buf.String())
		conn.Close()
		result = Port{PortNum: port, Open: true, Banner: banner}
	}
	resultsChan <- result
	<-sem
}

func CreateWorkers() {}

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
