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

		var wki2d rng.Range2D
		if portfirstjoin {
			wki2d = rng.NewRange2D(wki.Port.Start, wki.Port.End, wki.IP.Start, wki.IP.End)
		} else {
			wki2d = rng.NewRange2D(wki.IP.Start, wki.IP.End, wki.Port.Start, wki.Port.End)
		}

		for k := i + 1; k < len(wk); k++ {
			wkk := wk[k]

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
				tmp := make([]Rule, 0, len(tmp2d))
				for _, e := range tmp2d {
					if portfirstjoin {
						tmp = append(tmp, Rule{
							Name:     wkk.Name,
							Desc:     wkk.Desc,
							Allow:    wkk.Allow,
							Protocol: wkk.Protocol,
							Port:     rng.NewRange(e.R1.Start, e.R1.End),
							IP:       rng.NewRange(e.R2.Start, e.R2.End),
						})

					} else {
						tmp = append(tmp, Rule{
							Name:     wkk.Name,
							Desc:     wkk.Desc,
							Allow:    wkk.Allow,
							Protocol: wkk.Protocol,
							Port:     rng.NewRange(e.R2.Start, e.R2.End),
							IP:       rng.NewRange(e.R1.Start, e.R1.End),
						})
					}
				}
				wk = append(wk[:k], append(tmp, wk[k+1:]...)...)
				k += len(tmp) - 1
			}
		}

	}

	return wk
}
