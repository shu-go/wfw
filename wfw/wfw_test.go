package wfw_test

import (
	"testing"

	"github.com/shu-go/gotwant"
	"github.com/shu-go/rng"
	"github.com/shu-go/wfw/wfw"
)

func TestUnary(t *testing.T) {
	rule1 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(445), rng.Int(445)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}

	rs := wfw.RuleSet{rule1}
	rsrs := rs.Hoge(true)
	gotwant.Test(t, len(rsrs), 1)
	gotwant.Test(t, rsrs[0], rule1)
}
func TestNonIntersecting(t *testing.T) {
	rule1 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(445), rng.Int(445)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}
	rule2 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(3389), rng.Int(3389)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 52}, rng.IPv4{192, 168, 200, 52}),
	}

	rs := wfw.RuleSet{rule1, rule2}
	rsrs := rs.Hoge(true)
	gotwant.Test(t, len(rsrs), 2)
	gotwant.Test(t, rsrs[0].Port, rng.NewRange(rng.Int(445), rng.Int(445)))
	gotwant.Test(t, rsrs[0].IP, rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}))
	gotwant.Test(t, rsrs[1].Port, rng.NewRange(rng.Int(3389), rng.Int(3389)))
	gotwant.Test(t, rsrs[1].IP, rng.NewRange(rng.IPv4{192, 168, 200, 52}, rng.IPv4{192, 168, 200, 52}))
}

func TestPort(t *testing.T) {
	rule0 := wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}
	rule1 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(445), rng.Int(445)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}

	rs := wfw.RuleSet{rule1, rule0}
	rsrs := rs.Hoge(true)
	gotwant.Test(t, len(rsrs), 3)
	gotwant.Test(t, rsrs[0], wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(445), rng.Int(445)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	})
	gotwant.Test(t, rsrs[1], wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(444)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	})
	gotwant.Test(t, rsrs[2], wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(446), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	})

	t.Run("Reverse", func(t *testing.T) {
		rs := wfw.RuleSet{rule0, rule1}
		rsrs := rs.Hoge(true)
		gotwant.Test(t, len(rsrs), 1)
		gotwant.Test(t, rsrs[0], rule0)
	})
}

func TestIP(t *testing.T) {
	rule0 := wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}
	rule1 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 100}, rng.IPv4{192, 168, 200, 100}),
	}

	rs := wfw.RuleSet{rule1, rule0}
	rsrs := rs.Hoge(true)
	gotwant.Test(t, len(rsrs), 3)
	gotwant.Test(t, rsrs[0], wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 100}, rng.IPv4{192, 168, 200, 100}),
	})
	gotwant.Test(t, rsrs[1], wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 99}),
	})
	gotwant.Test(t, rsrs[2], wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(0), rng.Int(65535)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 101}, rng.IPv4{192, 168, 200, 255}),
	})

	t.Run("Reverse", func(t *testing.T) {
		rs := wfw.RuleSet{rule0, rule1}
		rsrs := rs.Hoge(true)
		gotwant.Test(t, len(rsrs), 1)
		gotwant.Test(t, rsrs[0], rule0)
	})
}

func TestCorner(t *testing.T) {
	rule0 := wfw.Rule{
		Allow:    false,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(100), rng.Int(200)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 1}, rng.IPv4{192, 168, 200, 255}),
	}
	rule1 := wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(150), rng.Int(250)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 100}, rng.IPv4{192, 168, 211, 100}),
	}

	rs := wfw.RuleSet{rule0, rule1}
	rsrs := rs.Hoge(true)
	gotwant.Test(t, len(rsrs), 3)
	gotwant.Test(t, rsrs[0], rule0)
	gotwant.Test(t, rsrs[1], wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(150), rng.Int(200)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 201, 1}, rng.IPv4{192, 168, 211, 100}),
	})
	gotwant.Test(t, rsrs[2], wfw.Rule{
		Allow:    true,
		Protocol: "TCP",
		Port:     rng.NewRange(rng.Int(201), rng.Int(250)),
		IP:       rng.NewRange(rng.IPv4{192, 168, 200, 100}, rng.IPv4{192, 168, 211, 100}),
	})
}
