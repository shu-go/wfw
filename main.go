package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shu-go/gli"
	"github.com/shu-go/rng"
	"github.com/shu-go/wfw/wfw"
)

// Version is app version
var Version string

func init() {
	if Version == "" {
		Version = "dev-" + time.Now().Format("20060102")
	}
}

type globalCmd struct {
	Input string
	Join  string `cli:"join,j" default:"ip" help:"join priority [ip, port]"`

	Format  string `cli:"format,f" help:"[list,cmd]" default:"list"`
	Enabled bool   `cli:"enabled" help:"if format=cmd" default:"no"`

	Gen genCmd
}

type RuleIF struct {
	Name, Desc string
	Protocol   string
	Allow      bool
	Ports      string `json:"Port"`
	IPs        string `json:"IP"`
}

func (c globalCmd) Run(args []string) error {
	if c.Input == "" {
		if len(args) == 0 {
			return errors.New("--input is empty")
		}
		c.Input = args[0]
	}

	if c.Join != "ip" && c.Join != "port" {
		return errors.New("--join must be ip or port")
	}

	file, err := os.Open(c.Input)
	if err != nil {
		return err
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	file.Close()

	var rules []RuleIF
	err = json.Unmarshal(content, &rules)
	if err != nil {
		return err
	}

	rs := wfw.RuleSet{}
	for _, rule := range rules {
		for _, p := range strings.Split(rule.Ports, ",") {
			pp := strings.Split(p, "-")
			var pr rng.Range
			if len(pp) > 1 {
				pr = rng.NewRange(Int(pp[0]), Int(pp[1]))
			} else {
				pr = rng.NewRange(Int(pp[0]), Int(pp[0]))
			}

			for _, ip := range strings.Split(rule.IPs, ",") {
				ipip := strings.Split(ip, "-")
				var ipr rng.Range
				if len(ipip) > 1 {
					ipr = rng.NewRange(rng.NewIPv4(strings.TrimSpace(ipip[0])), rng.NewIPv4(strings.TrimSpace(ipip[1])))
				} else {
					ipr = rng.NewRange(rng.NewIPv4(strings.TrimSpace(ipip[0])), rng.NewIPv4(strings.TrimSpace(ipip[0])))
				}

				r := wfw.Rule{
					Name:     rule.Name,
					Desc:     rule.Desc,
					Protocol: rule.Protocol,
					Allow:    rule.Allow,
					Port:     pr,
					IP:       ipr,
				}
				rs = append(rs, r)
			}
		}
	}

	result := rs.Hoge(c.Join == "port")

	rules = rules[:0]
	for _, r := range result {
		rif := RuleIF{
			Name:     r.Name,
			Desc:     r.Desc,
			Protocol: r.Protocol,
			Allow:    r.Allow,
			Ports:    StringifySeq(r.Port.Start) + "-" + StringifySeq(r.Port.End),
			IPs:      StringifySeq(r.IP.Start) + "-" + StringifySeq(r.IP.End),
		}
		if r.Port.Start.Equal(r.Port.End) {
			rif.Ports = StringifySeq(r.Port.Start)
		}
		if r.IP.Start.Equal(r.IP.End) {
			rif.IPs = StringifySeq(r.IP.Start)
		}
		rules = append(rules, rif)
	}

	// fix Ports, join IPs
	for i := len(rules) - 2; i >= 0; i-- {
		for k := i + 1; k < len(rules); k++ {
			if rules[k].Name == rules[i].Name && rules[k].Desc == rules[i].Desc && rules[k].Protocol == rules[i].Protocol && rules[k].Allow == rules[i].Allow &&
				rules[k].Ports == rules[i].Ports {
				//
				rules[i].IPs += "," + rules[k].IPs
				rules = append(rules[:k], rules[k+1:]...)
			}
		}
	}
	// fix IPs, join Ports
	for i := len(rules) - 2; i >= 0; i-- {
		for k := i + 1; k < len(rules); k++ {
			if rules[k].Name == rules[i].Name && rules[k].Desc == rules[i].Desc && rules[k].Protocol == rules[i].Protocol && rules[k].Allow == rules[i].Allow &&
				rules[k].IPs == rules[i].IPs {
				//
				rules[i].Ports += "," + rules[k].Ports
				rules = append(rules[:k], rules[k+1:]...)
			}
		}
	}

	for _, r := range rules {
		if c.Format == "cmd" {
			var enabled string
			if !c.Enabled {
				enabled = "enable=no"
			}

			name := "name=\"" + r.Name + "\""
			action := "action="
			if r.Allow {
				action += "allow"
			} else {
				action += "block"
			}

			var description string
			if len(r.Desc) != 0 {
				description = "description=\"" + r.Desc + "\""
			}

			remoteip := "remoteip=\"" + r.IPs + "\""
			localport := "localport=\"" + r.Ports + "\""
			protocol := "protocol=\"" + strings.ToLower(r.Protocol) + "\""

			if protocol != "protocol=\"tcp\"" && protocol != "protocol=\"udp\"" {
				localport = ""
			}

			fmt.Printf(
				"netsh advfirewall firewall add rule  %[1]s  %[2]s  %[3]s  dir=in  profile=any  %[4]s  %[5]s  %[6]s  %[7]s\n",
				name,
				enabled,
				description,
				action,
				protocol,
				localport,
				remoteip,
			)
		} else {
			var action string
			if r.Allow {
				action = "allow"
			} else {
				action = "BLOCK"
			}
			fmt.Printf(
				"----------------------------------------\n"+
					"Name: %[1]s\n"+
					"Desc: %[2]s\n"+
					"Action: %[3]s\n"+
					"Protocol: %[4]s\n"+
					"Port: %[5]s\n"+
					"IP: %[6]s\n",
				r.Name,
				r.Desc,
				action,
				r.Protocol,
				r.Ports,
				r.IPs,
			)
		}
	}

	return nil
}

type genCmd struct {
	Output string `default:"./example.json"`
}

func (c genCmd) Run() error {
	if c.Output == "" {
		return errors.New("--output is empty")
	}

	rules := []RuleIF{
		{
			Name:     "allow HTTP",
			Desc:     "1st priority",
			Protocol: "TCP",
			Allow:    true,
			Ports:    "80",
			IPs:      "192.168.0.101",
		},
		{
			Name:     "ban all 192.168",
			Desc:     "2nd priority",
			Protocol: "TCP",
			Allow:    false,
			Ports:    "0-65535",
			IPs:      "192.168.0.1-192.168.255.255",
		},
		{
			Name:     "ban all 192.168",
			Desc:     "3rd priority, this rule will be disappeared",
			Protocol: "TCP",
			Allow:    true,
			Ports:    "3389",
			IPs:      "192.168.0.101",
		},
	}

	content, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}

	file, err := os.Create(c.Output)
	if err != nil {
		return err
	}
	file.WriteString(string(content))
	file.Close()

	return nil
}

func Int(s string) rng.Int {
	i, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return rng.Int(0)
	}
	return rng.Int(i)
}

func StringifySeq(s rng.Sequential) string {
	if ip, ok := s.(rng.IPv4); ok {
		return fmt.Sprintf("%v.%v.%v.%v", ip[0], ip[1], ip[2], ip[3])
	} else if i, ok := s.(rng.Int); ok {
		return strconv.Itoa(int(i))
	}
	return ""
}

func main() {
	app := gli.NewWith(&globalCmd{})
	app.Name = "wfw"
	app.Desc = "generates Windows Fiirewall (netsh advfirewall) commands from JSON rules"
	app.Version = Version
	app.Usage = `wfw gen
wfw example.json
wfw --format cmd example.json`
	app.Copyright = "(C) 2021 Shuhei Kubota"
	app.Run(os.Args)
}
