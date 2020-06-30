package prober

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
)

func dialUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (net.Conn, error) {
	var dialProtocol string
	sourceAddr := &net.UDPAddr{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return nil, err
	}
	// select ip protocol for udp
	// default IPProtocol: ipv4
	// chooseProtocol return err if module.UDP.IPProtocol is empty
	// TODO lost ipv6 test
	if module.UDP.IPProtocol == "" {
		module.UDP.IPProtocol = "ip4"
	}
	ip, _, err := chooseProtocol(ctx, module.UDP.IPProtocol, module.UDP.IPProtocolFallback, targetAddress, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "udp6"
	} else {
		dialProtocol = "udp4"
	}

	if len(module.UDP.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(module.TCP.SourceIPAddress)
		if srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", module.TCP.SourceIPAddress)
			return nil, fmt.Errorf("error parsing source ip address: %s", module.TCP.SourceIPAddress)
		}
		level.Info(logger).Log("msg", "Using local address", "srcIP", srcIP)
		sAddr, err := net.ResolveUDPAddr(dialProtocol, ip.String()+":"+port)
		if err != nil {
			level.Error(logger).Log("error", "Can't resolve source address:", "error:", err)
			return nil, fmt.Errorf("can't resolve source address:%s", err)
		}
		sourceAddr = sAddr
	}
	// Build udp link address
	addr, err := net.ResolveUDPAddr(dialProtocol, ip.String()+":"+port)
	if err != nil {
		level.Error(logger).Log("error", "Can't resolve address:", "error:", err)
		return nil, fmt.Errorf("can't resolve address:%s", err)
	}
	level.Info(logger).Log("msg", "Dialing UDP")
	return net.DialUDP(dialProtocol, sourceAddr, addr)
}

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) bool {
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	deadline, _ := ctx.Deadline()

	conn, err := dialUDP(ctx, target, module, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error dialing UDP", "err", err)
		return false
	}
	defer conn.Close()
	level.Info(logger).Log("msg", "Successfully dialed")

	// Set a deadline to prevent the following code from blocking forever.
	// If a deadline cannot be set, better fail the probe by returning an error
	// now rather than blocking forever.
	if err := conn.SetDeadline(deadline); err != nil {
		level.Error(logger).Log("msg", "Error setting deadline", "err", err)
		return false
	}

	_, er := verifyConnect(logger, conn, probeFailedDueToRegex)
	if er != nil {
		level.Error(logger).Log("msg", "failed verifyQueryResponse", er)
		return false
	}

	return true
}

func verifyConnect(logger log.Logger, conn net.Conn, probeFailedDueToRegex prometheus.Gauge) (bool, error) {
	send := ""
	level.Debug(logger).Log("msg", "Sending line", "line", send)
	if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
		level.Error(logger).Log("msg", "Failed to send", "err", err)
		return false, err
	}
	// Read lines until one of them matches the configured regexp.
	// tip: max size of data: 1M
	data := make([]byte, 2<<9)
	_, errs := conn.Read(data)
	if errs != nil {
		fmt.Println("err:", errs)
		// return error: i/o timeout if udp server return nil
		// return error: read connection refused if udp server closed
		level.Debug(logger).Log("error", "cannot read msg from conn", errs)
		return false, errors.New("cannot read msg from conn")
	}
	return true, nil
}
