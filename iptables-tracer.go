package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"github.com/x-way/iptables-tracer/pkg/ctprint"
	"github.com/x-way/pktdump"
)

type iptablesRule struct {
	Table      string
	Chain      string
	Rule       string
	ChainEntry bool
}

type msg struct {
	Time    time.Time
	Rule    iptablesRule
	Mark    uint32
	Iif     string
	Oif     string
	Payload []byte
	Ct      []byte
	CtInfo  uint32
}

var (
	traceDuration  = flag.Duration("t", 10*time.Second, "how long to run the iptables-tracer")
	packetGap      = flag.Duration("g", 10*time.Millisecond, "output empty line when two loglines are separated by at least this duration")
	nflogGroup     = flag.Int("n", 22, "NFLOG group number to use")
	traceFilter    = flag.String("f", "-p udp --dport 53", "trace filter (iptables match syntax)")
	traceID        = flag.Int("i", 0, "trace id (0 = use PID)")
	traceRules     = flag.Bool("r", false, "trace rules in addition to chains (experimental, currently broken!)")
	clearRules     = flag.Bool("c", false, "clear all iptables-tracer iptables rules from running config")
	fwMark         = flag.Int("m", 0, "fwmark to use for packet tracking")
	packetLimit    = flag.Int("l", 0, "limit of packets per minute to trace (0 = no limit)")
	ip6tables      = flag.Bool("6", false, "use ip6tables")
	debugConntrack = flag.Bool("x", false, "dump all conntrack information")
	saveCommand    string
	restoreCommand string
)

func main() {
	// iptables-tracer -f "-s 192.0.2.1 -p tcp --dport 443" -t 30s
	flag.Parse()
	fmt.Printf("traceDuration: %+v\n", traceDuration)    // traceDuration: 10s
	fmt.Printf("packetGap: %+v\n", *packetGap)           // packetGap: 10ms
	fmt.Printf("nflogGroup: %+v\n", *nflogGroup)         // nflogGroup: 22
	fmt.Printf("traceFilter: %+v\n", *traceFilter)       // traceFilter: -p udp --dport 53
	fmt.Printf("traceID: %+v\n", *traceID)               // traceID: 0
	fmt.Printf("traceRules: %+v\n", *traceRules)         // traceRules: false
	fmt.Printf("clearRules: %+v\n", *clearRules)         // clearRules: false
	fmt.Printf("fwMark: %+v\n", *fwMark)                 // fwMark: 0
	fmt.Printf("packetLimit: %+v\n", *packetLimit)       // packetLimit: 0
	fmt.Printf("ip6tables: %+v\n", *ip6tables)           // ip6tables: false
	fmt.Printf("debugConntrack: %+v\n", *debugConntrack) // debugConntrack: false
	fmt.Printf("saveCommand: %+v\n", saveCommand)        // saveCommand:
	fmt.Printf("restoreCommand: %+v\n", restoreCommand)  // restoreCommand:
	fmt.Printf("%s\n", "===============================================")

	if *ip6tables {
		saveCommand = "ip6tables-save"
		restoreCommand = "ip6tables-restore"
	} else {
		saveCommand = "iptables-save"
		restoreCommand = "iptables-restore"
	}
	fmt.Printf("traceDuration: %+v\n", traceDuration)    // traceDuration: 10s
	fmt.Printf("packetGap: %+v\n", *packetGap)           // packetGap: 10ms
	fmt.Printf("nflogGroup: %+v\n", *nflogGroup)         // nflogGroup: 22
	fmt.Printf("traceFilter: %+v\n", *traceFilter)       // traceFilter: -p udp --dport 53
	fmt.Printf("traceID: %+v\n", *traceID)               // traceID: 0
	fmt.Printf("traceRules: %+v\n", *traceRules)         // traceRules: false
	fmt.Printf("clearRules: %+v\n", *clearRules)         // clearRules: false
	fmt.Printf("fwMark: %+v\n", *fwMark)                 // fwMark: 0
	fmt.Printf("packetLimit: %+v\n", *packetLimit)       // packetLimit: 0
	fmt.Printf("ip6tables: %+v\n", *ip6tables)           // ip6tables: false
	fmt.Printf("debugConntrack: %+v\n", *debugConntrack) // debugConntrack: false
	fmt.Printf("saveCommand: %+v\n", saveCommand)        // saveCommand: iptables-save
	fmt.Printf("restoreCommand: %+v\n", restoreCommand)  // restoreCommand: iptables-restore
	fmt.Printf("%s\n", "===============================================")

	var err error

	if *traceID == 0 {
		*traceID = os.Getpid()
	}
	fmt.Printf("traceDuration: %+v\n", traceDuration)    // traceDuration: 10s
	fmt.Printf("packetGap: %+v\n", *packetGap)           // packetGap: 10ms
	fmt.Printf("nflogGroup: %+v\n", *nflogGroup)         // nflogGroup: 22
	fmt.Printf("traceFilter: %+v\n", *traceFilter)       // traceFilter: -p udp --dport 53
	fmt.Printf("traceID: %+v\n", *traceID)               // traceID: 3063
	fmt.Printf("traceRules: %+v\n", *traceRules)         // traceRules: false
	fmt.Printf("clearRules: %+v\n", *clearRules)         // clearRules: false
	fmt.Printf("fwMark: %+v\n", *fwMark)                 // fwMark: 0
	fmt.Printf("packetLimit: %+v\n", *packetLimit)       // packetLimit: 0
	fmt.Printf("ip6tables: %+v\n", *ip6tables)           // ip6tables: false
	fmt.Printf("debugConntrack: %+v\n", *debugConntrack) // debugConntrack: false
	fmt.Printf("saveCommand: %+v\n", saveCommand)        // saveCommand: iptables-save
	fmt.Printf("restoreCommand: %+v\n", restoreCommand)  // restoreCommand: iptables-restore
	fmt.Printf("%s\n", "===============================================")

	if *clearRules {
		cleanupIptables(0) // 0 -> clear all IDs
		return
	}

	if (*packetLimit != 0 || *traceRules) && *fwMark == 0 {
		log.Fatal("Error: limit or trace rules requires fwmark")
	}

	// 执行 iptables-save 命令
	// iptables-save 命令用来备份所有的 iptables 配置
	// iptables-restore 命令用来还原 iptables 配置
	lines := iptablesSave()
	fmt.Printf("lines: %+v\n", lines)
	// lines: [
	// 	# Generated by iptables-save v1.4.21 on Fri Feb 23 11:54:28 2024
	// 	*filter
	// 	:INPUT ACCEPT [69515:55373413]
	// 	:FORWARD ACCEPT [0:0]
	// 	:OUTPUT ACCEPT [139678:127327180]
	// 	:CNI-ADMIN - [0:0]
	// 	:CNI-FORWARD - [0:0]
	// 	:CNI-ISOLATION-STAGE-1 - [0:0]
	// 	:CNI-ISOLATION-STAGE-2 - [0:0]
	// 	:KUBE-FIREWALL - [0:0]
	// 	:KUBE-FORWARD - [0:0]
	// 	:KUBE-IPVS-FILTER - [0:0]
	// 	:KUBE-KUBELET-CANARY - [0:0]
	// 	...
	// 	COMMIT
	// 	# Completed on Fri Feb 23 11:59:21 2024

	// ]

	newIptablesConfig, ruleMap, maxLength := extendIptablesPolicy(lines, *traceID, *traceFilter, *fwMark, *packetLimit, *traceRules, *nflogGroup)
	fmt.Printf("newIptablesConfig: %+v\n", newIptablesConfig) // newIptablesConfig: []  []string
	fmt.Printf("ruleMap: %+v\n", ruleMap)                     // ruleMap: map[]  map[int]iptablesRule
	fmt.Printf("maxLength: %+v\n", maxLength)                 // maxLength: 0  int

	// 执行 iptables-restore 命令
	// iptables-save 命令用来备份所有的 iptables 配置
	// iptables-restore 命令用来还原 iptables 配置
	iptablesRestore(newIptablesConfig)

	defer cleanupIptables(*traceID)

	var nf *nflog.Nflog
	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.CopyPacket,
		Flags:       nflog.FlagConntrack,
		ReadTimeout: time.Second,
	}
	nf, err = nflog.Open(&config)
	if err != nil {
		log.Fatal(err)
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *traceDuration)
	defer cancel()

	msgChannel := make(chan msg)

	// type Attribute struct {
	// 	Hook       *uint8
	// 	Mark       *uint32
	// 	Timestamp  *time.Time
	// 	InDev      *uint32
	// 	PhysInDev  *uint32
	// 	OutDev     *uint32
	// 	PhysOutDev *uint32
	// 	Payload    *[]byte
	// 	Prefix     *string
	// 	UID        *uint32
	// 	Seq        *uint32
	// 	SeqGlobal  *uint32
	// 	GID        *uint32
	// 	HwType     *uint16
	// 	HwAddr     *[]byte
	// 	HwHeader   *[]byte
	// 	HwLen      *uint16
	// 	HwProtocol *uint16
	// 	CtInfo     *uint32
	// 	Ct         *[]byte
	// }
	callback := func(m nflog.Attribute) int {
		fmt.Printf("%s\n", "********************************************")
		fmt.Printf("Hook: %+v\n", *m.Hook)
		fmt.Printf("Mark: %+v\n", *m.Mark)
		fmt.Printf("Timestamp: %+v\n", *m.Timestamp)
		fmt.Printf("InDev: %+v\n", *m.InDev)
		fmt.Printf("PhysInDev: %+v\n", *m.PhysInDev)
		fmt.Printf("OutDev: %+v\n", *m.OutDev)
		fmt.Printf("PhysOutDev: %+v\n", *m.PhysOutDev)
		fmt.Printf("Payload: %+v\n", *m.Payload)
		fmt.Printf("Prefix: %+v\n", *m.Prefix)
		fmt.Printf("UID: %+v\n", *m.UID)
		fmt.Printf("Seq: %+v\n", *m.Seq)
		fmt.Printf("SeqGlobal: %+v\n", *m.SeqGlobal)
		fmt.Printf("GID: %+v\n", *m.GID)
		fmt.Printf("HwType: %+v\n", *m.HwType)
		fmt.Printf("HwAddr: %+v\n", *m.HwAddr)
		fmt.Printf("HwHeader: %+v\n", *m.HwHeader)
		fmt.Printf("HwLen: %+v\n", *m.HwLen)
		fmt.Printf("HwProtocol: %+v\n", *m.HwProtocol)
		fmt.Printf("CtInfo: %+v\n", *m.CtInfo)
		fmt.Printf("Ct: %+v\n", *m.Ct)
		fmt.Printf("%s\n", "********************************************")

		var prefix string
		if m.Prefix != nil {
			prefix = *m.Prefix
		}
		prefixRe := regexp.MustCompile(`^iptr:(\d+):(\d+)`)
		if res := prefixRe.FindStringSubmatch(prefix); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == *traceID {
				ruleID, _ := strconv.Atoi(res[2])
				if myRule, ok := ruleMap[ruleID]; ok {
					var fwMark uint32
					var iif string
					var oif string
					var ctBytes []byte
					ctInfo := ^uint32(0)
					if m.Mark != nil {
						fwMark = *m.Mark
					}
					if m.InDev != nil {
						iif = GetIfaceName(*m.InDev)
					}
					if m.OutDev != nil {
						oif = GetIfaceName(*m.OutDev)
					}
					if m.Ct != nil {
						ctBytes = *m.Ct
					}
					if m.CtInfo != nil {
						ctInfo = *m.CtInfo
					}
					if m.Payload != nil {
						msgChannel <- msg{
							Time:    time.Now(),
							Rule:    myRule,
							Mark:    fwMark,
							Iif:     iif,
							Oif:     oif,
							Payload: *m.Payload,
							Ct:      ctBytes,
							CtInfo:  ctInfo,
						}
					}
				}
			}
		}
		return 0
	}

	go func() {
		var lastTime time.Time
		for msg := range msgChannel {
			if msg.Time.Sub(lastTime).Nanoseconds() > (*packetGap).Nanoseconds() && !lastTime.IsZero() {
				fmt.Println("")
			}
			lastTime = msg.Time
			printRule(maxLength, msg.Time, msg.Rule, msg.Mark, msg.Iif, msg.Oif, msg.Payload, msg.Ct, msg.CtInfo)
			if *debugConntrack && len(msg.Ct) > 0 {
				ctprint.Print(msg.Ct)
			}
		}
	}()

	errorFunc := func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		log.Fatalf("Could not receive message: %v\n", err)
		return 1
	}

	err = nf.RegisterWithErrorFunc(ctx, callback, errorFunc)
	if err != nil {
		log.Fatal(err)
	}

	// block until context expires
	<-ctx.Done()
	close(msgChannel)
}

func printRule(maxLength int, ts time.Time, rule iptablesRule, fwMark uint32, iif, oif string, payload, ct []byte, ctInfo uint32) {
	packetStr := ""
	if *ip6tables {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default))
	} else {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))
	}
	ctStr := fmt.Sprintf(" %s 0x%08x", ctprint.InfoString(ctInfo), ctprint.GetCtMark(ct))
	if rule.ChainEntry {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds 0x%%08x%%s %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, fwMark, ctStr, packetStr, iif, oif)
	} else {
		fmtStr := fmt.Sprintf("%%s %%-6s %%-%ds %%s 0x%%08x%%s %%s  [In:%%s Out:%%s]\n", maxLength)
		fmt.Printf(fmtStr, ts.Format("15:04:05.000000"), rule.Table, rule.Chain, rule.Rule, fwMark, ctStr, packetStr, iif, oif)
	}
}

func writeToCommand(cmd *exec.Cmd, lines []string) error {
	cmdWriter, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := io.WriteString(cmdWriter, line+"\n"); err != nil {
			log.Fatal(err)
		}
	}
	cmdWriter.Close()
	return cmd.Wait()
}

func readFromCommand(cmd *exec.Cmd) ([]string, error) {
	var cmdReader io.ReadCloser
	var lines []string
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		return lines, err
	}
	scanner := bufio.NewScanner(cmdReader)
	if err = cmd.Start(); err != nil {
		return lines, err
	}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err = scanner.Err(); err != nil {
		return lines, err
	}
	if err = cmd.Wait(); err != nil {
		return lines, err
	}
	return lines, nil
}

func iptablesSave() []string {
	var err error
	var lines []string

	if lines, err = readFromCommand(exec.Command(saveCommand)); err != nil {
		log.Fatal(err)
	}

	return lines
}

func iptablesRestore(policy []string) {
	// restoreCommand: iptables-restore
	if err := writeToCommand(exec.Command(restoreCommand, "-t"), policy); err != nil {
		log.Fatal(err)
	}
	if err := writeToCommand(exec.Command(restoreCommand), policy); err != nil {
		log.Fatal(err)
	}
}

func cleanupIptables(cleanupID int) {
	iptablesRestore(clearIptablesPolicy(iptablesSave(), cleanupID))
}

// GetIfaceName takes a network interface index and returns the corresponding name
func GetIfaceName(index uint32) string {
	var iface *net.Interface
	var err error
	if iface, err = net.InterfaceByIndex(int(index)); err != nil {
		return ""
	}
	return iface.Name
}
