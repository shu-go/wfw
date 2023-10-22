package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	svg "github.com/ajstarks/svgo"
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
	Input string `cli:"input,i" help:"rule file. use 'wfw gen' to generate example.json"`

	Aggregation string `cli:"aggregation,a"  default:"ip"  help:"aggregates by [ip,port] first"`

	Format  string `cli:"format,f" help:"{list,json,cmd,svg}" default:"list"`
	Enabled bool   `cli:"enabled" help:"if --format=cmd" default:"no"`

	SVGDir        string `cli:"svg-dir,sd" default:"." help:"svg output dir"`
	SVGNameFormat string `cli:"svg-name-format,sf" default:"%_{aggregation}_{protocol}.svg" help:"a name format for files in --svg-dir. % is the name of a rule"`

	Except string `cli:"except" default:"(Except: %)" help:"suffix of the name, explaining causes of splitting rules"`

	Gen genCmd `help:"generates an example rule file"`
}

type RuleIF struct {
	Name, Desc string
	Allow      bool
	Protocol   string
	Ports      string `json:"Port"`
	IPs        string `json:"IP"`
	tag        int
}

func (c globalCmd) Run(args []string) error {
	if c.Input == "" {
		if len(args) == 0 {
			return errors.New("--input is empty")
		}
		c.Input = args[0]
	}

	c.Aggregation = strings.ToLower(c.Aggregation)
	if c.Aggregation != "ip" && c.Aggregation != "port" {
		return errors.New("--aggregation must be ip or port")
	}

	c.Format = strings.ToLower(c.Format)
	if c.Format != "list" && c.Format != "json" && c.Format != "cmd" && c.Format != "svg" {
		return errors.New("--format must be list,json,cmd or svg")
	}

	file, err := os.Open(c.Input)
	if err != nil {
		return err
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	file.Close()

	var inRuleIFs []RuleIF
	err = json.Unmarshal(content, &inRuleIFs)
	if err != nil {
		return err
	}

	// tagging
	for i := range inRuleIFs {
		inRuleIFs[i].tag = i
	}

	inRS := wfw.RuleSet{}
	for _, rif := range inRuleIFs {
		if strings.HasPrefix(rif.Name, "#") {
			continue
		}
		inRS = append(inRS, ruleIFToRuleSet(rif)...)
	}

	result := inRS.Hoge(c.Aggregation == "port")

	ruleIFs := ruleIFsFromRuleSet(result, c.Except, inRuleIFs)

	joinRuleIFs(&ruleIFs, c.Aggregation)

	if c.Format == "json" {
		content, err := json.MarshalIndent(ruleIFs, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(content))

		return nil
	}

	if c.Format == "svg" {
		name := c.Input
		if ext := filepath.Ext(name); ext != "" {
			name = name[:len(name)-len(ext)]
		}
		err := saveAsSVG(ruleIFs, name, c.SVGDir, c.SVGNameFormat, c.Aggregation)
		if err != nil {
			return err
		}
		return nil
	}

	// c.Format is "cmd" or "list"

	newline, err := regexp.Compile(`\r\n|\r|\n`)
	if err != nil {
		return err
	}

	for _, rif := range ruleIFs {
		if c.Format == "cmd" {
			var enabled string
			if !c.Enabled {
				enabled = "enable=no"
			}

			name := "name=\"" + newline.ReplaceAllLiteralString(rif.Name, " ") + "\""
			action := "action="
			if rif.Allow {
				action += "allow"
			} else {
				action += "block"
			}

			var description string
			if len(rif.Desc) != 0 {
				description = "description=\"" + newline.ReplaceAllLiteralString(rif.Desc, " ") + "\""
			}

			remoteip := "remoteip=\"" + rif.IPs + "\""
			localport := "localport=\"" + rif.Ports + "\""
			protocol := "protocol=\"" + strings.ToLower(rif.Protocol) + "\""

			if protocol != "protocol=\"tcp\"" && protocol != "protocol=\"udp\"" {
				localport = ""
			}

			fmt.Printf(
				"netsh advfirewall firewall add rule  %[1]s  %[2]s  %[3]s  dir=in  profile=any  %[4]s  %[5]s  %[6]s  %[7]s\r\n",
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
			if rif.Allow {
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
				rif.Name,
				rif.Desc,
				action,
				rif.Protocol,
				rif.Ports,
				rif.IPs,
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
			Name:     "allow HTTPS",
			Desc:     "1st priority",
			Allow:    true,
			Protocol: "TCP",
			Ports:    "443",
			IPs:      "192.168.0.1-192.168.255.255",
		},
		{
			Name:     "allow HTTP from .0.101",
			Desc:     "2nd priority",
			Allow:    true,
			Protocol: "TCP",
			Ports:    "80,443,8080",
			IPs:      "192.168.0.101",
		},
		{
			Name:     "deny TCP from 192.168.",
			Desc:     "3rd priority",
			Allow:    false,
			Protocol: "TCP",
			Ports:    "0-65535",
			IPs:      "192.168.0.1-192.168.255.255",
		},
		{
			Name:     "deny UDP from 192.168.",
			Desc:     "3rd priority",
			Allow:    false,
			Protocol: "UDP",
			Ports:    "0-65535",
			IPs:      "192.168.0.1-192.168.255.255",
		},
		{
			Name:     "allow RDP from .0.101",
			Desc:     "4th priority, this rule will be disappeared",
			Allow:    true,
			Protocol: "TCP",
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

// origIFs is referred on building Excepts
func ruleIFsFromRuleSet(rs wfw.RuleSet, exceptFormat string, origIFs []RuleIF) []RuleIF {
	var ruleIFs []RuleIF
	for _, r := range rs {
		name := r.Name

		if exceptFormat != "" {
			if len(r.Excepts) > 0 {
				names := make([]string, 0, len(r.Excepts))
				for t, v := range r.Excepts {
					nm := ""
					if t < len(origIFs) {
						nm = origIFs[t].Name
					}

					if v {
						names = append(names, nm)
					}
				}
				name += strings.Replace(exceptFormat, "%", strings.Join(names, ", "), 1)
			}
		}

		rif := RuleIF{
			Name:     name, //r.Name,
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
		ruleIFs = append(ruleIFs, rif)
	}

	return ruleIFs
}

func joinRuleIFs(ruleIFs *[]RuleIF, aggregation string) {
	if aggregation == "port" {
		// fix Ports, join IPs
		for i := len((*ruleIFs)) - 2; i >= 0; i-- {
			for k := i + 1; k < len((*ruleIFs)); k++ {
				if (*ruleIFs)[k].tag == (*ruleIFs)[i].tag && (*ruleIFs)[k].Protocol == (*ruleIFs)[i].Protocol && (*ruleIFs)[k].Allow == (*ruleIFs)[i].Allow &&
					(*ruleIFs)[k].Ports == (*ruleIFs)[i].Ports {
					//
					(*ruleIFs)[i].IPs += "," + (*ruleIFs)[k].IPs
					(*ruleIFs) = append((*ruleIFs)[:k], (*ruleIFs)[k+1:]...)
				}
			}
		}
		// fix IPs, join Ports
		for i := len((*ruleIFs)) - 2; i >= 0; i-- {
			for k := i + 1; k < len((*ruleIFs)); k++ {
				if (*ruleIFs)[k].tag == (*ruleIFs)[i].tag && (*ruleIFs)[k].Protocol == (*ruleIFs)[i].Protocol && (*ruleIFs)[k].Allow == (*ruleIFs)[i].Allow &&
					(*ruleIFs)[k].IPs == (*ruleIFs)[i].IPs {
					//
					(*ruleIFs)[i].Ports += "," + (*ruleIFs)[k].Ports
					(*ruleIFs) = append((*ruleIFs)[:k], (*ruleIFs)[k+1:]...)
				}
			}
		}
	} else {
		// fix IPs, join Ports
		for i := len((*ruleIFs)) - 2; i >= 0; i-- {
			for k := i + 1; k < len((*ruleIFs)); k++ {
				if (*ruleIFs)[k].tag == (*ruleIFs)[i].tag && (*ruleIFs)[k].Protocol == (*ruleIFs)[i].Protocol && (*ruleIFs)[k].Allow == (*ruleIFs)[i].Allow &&
					(*ruleIFs)[k].IPs == (*ruleIFs)[i].IPs {
					//
					(*ruleIFs)[i].Ports += "," + (*ruleIFs)[k].Ports
					(*ruleIFs) = append((*ruleIFs)[:k], (*ruleIFs)[k+1:]...)
				}
			}
		}
		// fix Ports, join IPs
		for i := len((*ruleIFs)) - 2; i >= 0; i-- {
			for k := i + 1; k < len((*ruleIFs)); k++ {
				if (*ruleIFs)[k].tag == (*ruleIFs)[i].tag && (*ruleIFs)[k].Protocol == (*ruleIFs)[i].Protocol && (*ruleIFs)[k].Allow == (*ruleIFs)[i].Allow &&
					(*ruleIFs)[k].Ports == (*ruleIFs)[i].Ports {
					//
					(*ruleIFs)[i].IPs += "," + (*ruleIFs)[k].IPs
					(*ruleIFs) = append((*ruleIFs)[:k], (*ruleIFs)[k+1:]...)
				}
			}
		}
	}
}

func ruleIFToRuleSet(rif RuleIF) wfw.RuleSet {
	var rs wfw.RuleSet

	for _, p := range strings.Split(rif.Ports, ",") {
		pp := strings.Split(p, "-")
		var pr rng.Range
		if len(pp) > 1 {
			pr = rng.NewRange(Int(pp[0]), Int(pp[1]))
		} else {
			pr = rng.NewRange(Int(pp[0]), Int(pp[0]))
		}

		for _, ip := range strings.Split(rif.IPs, ",") {
			ipip := strings.Split(ip, "-")
			var ipr rng.Range
			if len(ipip) > 1 {
				ipr = rng.NewRange(rng.NewIPv4(strings.TrimSpace(ipip[0])), rng.NewIPv4(strings.TrimSpace(ipip[1])))
			} else {
				ipr = rng.NewRange(rng.NewIPv4(strings.TrimSpace(ipip[0])), rng.NewIPv4(strings.TrimSpace(ipip[0])))
			}

			r := wfw.Rule{
				Name:     rif.Name,
				Desc:     rif.Desc,
				Protocol: rif.Protocol,
				Allow:    rif.Allow,
				Port:     pr,
				IP:       ipr,
				Original: true,
				Tag:      rif.tag,
			}
			rs = append(rs, r)
		}
	}

	return rs
}

func saveAsSVG(ruleIFs []RuleIF, dest, dir, nameFormat, aggregation string) error {
	protocolSet := make(map[string]struct{})
	portSet := make(map[rng.Int]struct{})
	ipSet := make(map[rng.IPv4]struct{})

	rs := wfw.RuleSet{}
	for i := range ruleIFs {
		// set tag based on a result rule set
		ruleIFs[i].tag = i

		// convert from []RuleIF to RuleSet back again
		rsrs := ruleIFToRuleSet(ruleIFs[i])

		for _, r := range rsrs {
			// scan ports and ips
			portSet[r.Port.Start.(rng.Int)] = struct{}{}
			portSet[r.Port.End.(rng.Int)] = struct{}{}
			ipSet[r.IP.Start.(rng.IPv4)] = struct{}{}
			ipSet[r.IP.End.(rng.IPv4)] = struct{}{}
			protocolSet[r.Protocol] = struct{}{}
		}

		rs = append(rs, rsrs...)
	}

	var ports []rng.Int
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Less(ports[j])
	})

	var ips []rng.IPv4
	for i := range ipSet {
		ips = append(ips, i)
	}
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].Less(ips[j])
	})

	const leftMargin = 120
	const topMargin = 50
	const cellSize = 50
	const fontSize = 12

	width := leftMargin + len(ports)*cellSize
	height := topMargin + len(ips)*cellSize + fontSize*5

	wk := make(wfw.RuleSet, 0, len(rs))
	for protocol := range protocolSet {
		wk = wk[:0]
		for i := range rs {
			if rs[i].Protocol == protocol {
				wk = append(wk, rs[i])
			}
		}

		var file *os.File
		var canvas *svg.SVG
		if dest == "stdout" {
			canvas = svg.New(os.Stdout)
		} else {
			name := strings.Replace(nameFormat, "%", dest, -1)
			name = strings.Replace(name, "{protocol}", protocol, -1)
			name = strings.Replace(name, "{aggregation}", aggregation, -1)

			var err error
			file, err = os.Create(filepath.Join(dir, name))
			if err != nil {
				return err
			}

			canvas = svg.New(file)
		}
		canvas.Start(width, height)

		canvas.Style("text/css", `rect.allow{fill:lightblue}
rect.block{fill:darkred}
rect.allow.onmouse{fill:lightcyan}
rect.block.onmouse{fill:red}
rect:hover{stroke:green}
@media (prefers-color-scheme: dark) {
    :root {
        background-color: black;
        fill: white;
    }
}
`)

		for y, p := range ips {
			ip := fmt.Sprintf("%v", p)
			canvas.Text(0, topMargin+y*cellSize+cellSize/2, ip, "font-size:"+strconv.Itoa(fontSize)+"px; dominant-baseline:central")
		}
		for x, p := range ports {
			port := fmt.Sprintf("%v", p)
			canvas.Text(leftMargin+x*cellSize+cellSize/2, topMargin, port, "font-size:"+strconv.Itoa(fontSize)+"px; text-anchor:middle")
		}

		// info
		canvas.Text(leftMargin, topMargin+len(ips)*cellSize+fontSize*1, "", "font-size:"+strconv.Itoa(fontSize)+"px", `class="wfw-name"`)
		canvas.Text(leftMargin, topMargin+len(ips)*cellSize+fontSize*2, "", "font-size:"+strconv.Itoa(fontSize)+"px", `class="wfw-desc"`)
		canvas.Text(leftMargin, topMargin+len(ips)*cellSize+fontSize*3, "", "font-size:"+strconv.Itoa(fontSize)+"px", `class="wfw-allow"`)
		canvas.Text(leftMargin, topMargin+len(ips)*cellSize+fontSize*4, "", "font-size:"+strconv.Itoa(fontSize)+"px", `class="wfw-ip"`)
		canvas.Text(leftMargin, topMargin+len(ips)*cellSize+fontSize*5, "", "font-size:"+strconv.Itoa(fontSize)+"px", `class="wfw-port"`)

		canvas.Translate(leftMargin, topMargin)

		for i := len(wk) - 1; i >= 0; i-- {
			left, right := 0, 0
			for k, p := range ports {
				if wk[i].Port.Start.Equal(p) {
					left = k
				}
				if wk[i].Port.End.Equal(p) {
					right = k
				}
			}
			top, bottom := 0, 0
			for k, p := range ips {
				if wk[i].IP.Start.Equal(p) {
					top = k
				}
				if wk[i].IP.End.Equal(p) {
					bottom = k
				}
			}

			basetop := i * 5 * 0

			left *= cellSize
			top *= cellSize
			if right != 0 {
				right = (right+1)*cellSize - 1
			}
			if bottom != 0 {
				bottom = (bottom+1)*cellSize - 1
			}

			if left == right {
				right += 10
			}

			if top == bottom {
				bottom += 10
			}

			allowclass := "allow"
			if !wk[i].Allow {
				allowclass = "block"
			}

			//opacity := strconv.FormatFloat(1.0-0.01*float64(i), 'f', 1, 64)

			var rif RuleIF
			for k := range ruleIFs {
				if ruleIFs[k].tag == wk[i].Tag {
					rif = ruleIFs[k]
				}
			}

			canvas.Rect(
				left,
				basetop+top,
				right-left,
				basetop+(bottom-top),
				//"fill-opacity:"+opacity,
				`class="rule-`+strconv.Itoa(wk[i].Tag)+` `+allowclass+` "`,
				`wfw-name="`+rif.Name+`"`,
				`wfw-desc="`+rif.Desc+`"`,
				`wfw-allow="`+allowclass+`"`,
				`wfw-ip="`+rif.IPs+`"`,
				`wfw-port="`+rif.Ports+`"`,
			)
		}

		canvas.Gend()

		canvas.Script("text/javascript", `for (var r of document.querySelectorAll("rect")) {
    r.addEventListener("mouseover", function() {
        var rule = ""
        for (var c of this.classList) {
            if (c.startsWith("rule")) {
                rule = c
                break
            }
        }
        if (rule=="") return
        document.getElementsByClassName("wfw-name")[0].textContent = this.getAttribute("wfw-name")
        document.getElementsByClassName("wfw-desc")[0].textContent = this.getAttribute("wfw-desc")
        document.getElementsByClassName("wfw-allow")[0].textContent = this.getAttribute("wfw-allow")
        document.getElementsByClassName("wfw-ip")[0].textContent = this.getAttribute("wfw-ip")
        document.getElementsByClassName("wfw-port")[0].textContent = this.getAttribute("wfw-port")
        for (var rr of document.getElementsByClassName(rule)) {
            rr.classList.add("onmouse")
        }
    }, false);
    r.addEventListener("mouseleave", function() {
        var rule = ""
        for (var c of this.classList) {
            if (c.startsWith("rule")) {
                rule = c
                break
            }
        }
        if (rule=="") return
        document.getElementsByClassName("wfw-name")[0].textContent = ""
        document.getElementsByClassName("wfw-desc")[0].textContent = ""
        document.getElementsByClassName("wfw-allow")[0].textContent = ""
        document.getElementsByClassName("wfw-ip")[0].textContent = ""
        document.getElementsByClassName("wfw-port")[0].textContent = ""
        for (var rr of document.getElementsByClassName(rule)) {
            rr.classList.remove("onmouse")
        }
    }, false);
}`)
		canvas.End()

		if file != nil {
			file.Close()
			file = nil
		}
	}

	return nil
}

func main() {
	app := gli.NewWith(&globalCmd{})
	app.Name = "wfw"
	app.Desc = "generates Windows Firewall (netsh advfirewall) commands from JSON rules"
	app.Version = Version
	app.Usage = `wfw gen
wfw example.json
wfw --format cmd example.json`
	app.Copyright = "(C) 2021 Shuhei Kubota"
	app.SuppressErrorOutput = true
	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

}
