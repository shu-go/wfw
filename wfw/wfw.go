package wfw

import (
	"github.com/shu-go/rng"
)

type Rule struct {
	Name, Desc string

	Protocol string

	Allow bool
	Port  rng.Range
	IP    rng.Range

	Original bool
	Excepts  map[ /*Tag*/ int]Except

	Tag int
}

type Except struct {
	Port, IP bool
}

func (r Rule) Equal(a Rule) bool {
	if r.Protocol != a.Protocol {
		return false
	}

	if r.Allow != a.Allow {
		return false
	}

	if !r.Port.Equal(a.Port) {
		return false
	}

	if !r.IP.Equal(a.IP) {
		return false
	}

	return true
}

type RuleSet []Rule

func (rs RuleSet) Hoge(portfirstjoin bool) RuleSet {
	/*
	 * r0
	 * r1  <--+-(1) wki
	 * r2  <--+     wkk
	 */

	/*
	 * r0    <--+-(2) wki
	 * r1    *--+     wkk
	 * r2    *--+     wkk
	 * r2-1  *--+     wkk
	 */

	wk := make(RuleSet, len(rs))
	copy(wk, rs)

	for i := len(wk) - 2; i >= 0; i-- {
		wki := wk[i]

		//rog.Print("")
		//rog.Printf("wki: %#v", wki)

		var wki2d rng.Range2D
		if portfirstjoin {
			wki2d = rng.NewRange2D(wki.Port.Start, wki.Port.End, wki.IP.Start, wki.IP.End)
		} else {
			wki2d = rng.NewRange2D(wki.IP.Start, wki.IP.End, wki.Port.Start, wki.Port.End)
		}

		for k := i + 1; k < len(wk); k++ {
			wkk := wk[k]

			//rog.Print("")
			//rog.Printf("  wkk: %#v", wkk)

			if wki.Protocol == wkk.Protocol {
				if wki.Allow == wkk.Allow {
					continue
				}

				var wkk2d rng.Range2D
				if portfirstjoin {
					wkk2d = rng.NewRange2D(wkk.Port.Start, wkk.Port.End, wkk.IP.Start, wkk.IP.End)
				} else {
					wkk2d = rng.NewRange2D(wkk.IP.Start, wkk.IP.End, wkk.Port.Start, wkk.Port.End)
				}
				tmp2d := wkk2d.Minus(wki2d)
				tmpIsOrig := (len(tmp2d) == 1 && tmp2d[0].R1.Equal(wkk2d.R1) && tmp2d[0].R2.Equal(wkk2d.R2))
				tmp := make([]Rule, 0, len(tmp2d))
				for _, e := range tmp2d {
					//rog.Printf("    e: %#v", e)

					excepts := wkk.Excepts

					var ipexcept, portexcept bool
					if portfirstjoin {
						portexcept = !e.R1.Equal(wkk2d.R1) && !e.R1.Equal(wki2d.R1)
						ipexcept = !e.R2.Equal(wkk2d.R2) && !e.R2.Equal(wki2d.R2)
					} else {
						portexcept = !e.R2.Equal(wkk2d.R2) && !e.R2.Equal(wki2d.R2)
						ipexcept = !e.R1.Equal(wkk2d.R1) && !e.R1.Equal(wki2d.R1)
					}
					//rog.Printf("      portexcept=%v, ipexcept=%v", portexcept, ipexcept)

					if !tmpIsOrig && wki.Original && (ipexcept || portexcept) {
						excepts = make(map[int]Except)
						if wki.Excepts != nil {
							// copy
							for k, v := range wki.Excepts {
								excepts[k] = v
							}
						}

						if e, found := excepts[wki.Tag]; found {
							excepts[wki.Tag] = Except{IP: e.IP || ipexcept, Port: e.Port || portexcept}
						} else {
							excepts[wki.Tag] = Except{IP: ipexcept, Port: portexcept}
						}
					}
					//rog.Printf("      excepts=%#v", excepts)

					if portfirstjoin {
						tmp = append(tmp, Rule{
							Name:     wkk.Name,
							Desc:     wkk.Desc,
							Allow:    wkk.Allow,
							Protocol: wkk.Protocol,
							Port:     rng.NewRange(e.R1.Start, e.R1.End),
							IP:       rng.NewRange(e.R2.Start, e.R2.End),
							Original: tmpIsOrig,
							Excepts:  excepts,
							Tag:      wkk.Tag,
						})

					} else {
						tmp = append(tmp, Rule{
							Name:     wkk.Name,
							Desc:     wkk.Desc,
							Allow:    wkk.Allow,
							Protocol: wkk.Protocol,
							Port:     rng.NewRange(e.R2.Start, e.R2.End),
							IP:       rng.NewRange(e.R1.Start, e.R1.End),
							Original: tmpIsOrig,
							Excepts:  excepts,
							Tag:      wkk.Tag,
						})
					}
				}
				wk = append(wk[:k], append(tmp, wk[k+1:]...)...)
				k += len(tmp) - 1
			}
		}
	}

	// remove each rule contained in another rule
	for i := len(wk) - 1; i >= 0; i-- {
		contained := false
		for k := 0; k < len(wk); k++ {
			if i == k {
				continue
			}

			if wk[i].Protocol == wk[k].Protocol && wk[i].Allow == wk[k].Allow &&
				wk[k].Port.ContainsRange(wk[i].Port) && wk[k].IP.ContainsRange(wk[i].IP) {
				//
				contained = true
				break
			}
		}
		if contained {
			wk = append(wk[:i], wk[i+1:]...)
		}
	}

	return wk
}
