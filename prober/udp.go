package prober

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
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
		if err !=nil {
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

	// verify connect response
	verifyConn := frontVerify(module.UDP.ConnectResponse)
	if verifyConn == false {
		level.Error(logger).Log("msg", "Error find connect response")
		return false
	}

	_, er :=verifyQueryResponse(module.UDP.ConnectResponse, logger, conn, probeFailedDueToRegex)
	if er != nil {
		level.Error(logger).Log("msg", "failed verifyQueryResponse", er)
		return false
	}

	// verify query response
	for i, qr := range module.UDP.QueryResponse {
		qrRes := frontVerify(qr)
		if qrRes == false {
			level.Error(logger).Log("msg", "Error find connect response")
			return false
		}

		level.Info(logger).Log("msg", "Processing query response entry", "entry_number", i)
		_, err :=verifyQueryResponse(qr, logger, conn, probeFailedDueToRegex)
		if err != nil {
			level.Error(logger).Log("msg", "failed verifyQueryResponse")
			return false
		}
	}
	return true
}

func verifyQueryResponse(qr config.QueryResponse, logger log.Logger, conn net.Conn, probeFailedDueToRegex prometheus.Gauge) (bool, error) {
	send := qr.Send
	if send != "" {
		level.Debug(logger).Log("msg", "Sending line", "line", send)
		if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
			level.Error(logger).Log("msg", "Failed to send", "err", err)
			return false, err
		}
	}
	if qr.Expect != "" {
		re, err := regexp.Compile(qr.Expect)
		if err != nil {
			level.Error(logger).Log("msg", "Could not compile into regular expression", "regexp", qr.Expect, "err", err)
			return false, err
		}
		var match []int
		// Read lines until one of them matches the configured regexp.
		data := make([]byte, 255)
		_, err = conn.Read(data)
		if err != nil {
			level.Debug(logger).Log("error", "cannot read msg from conn", err)
			return false, errors.New("cannot read msg from conn")
		}
		match = re.FindSubmatchIndex(data)
		if match != nil {
			level.Info(logger).Log("msg", "Regexp matched", "regexp", re, "line", string(data))
		}
		if match == nil {
			probeFailedDueToRegex.Set(1)
			level.Error(logger).Log("msg", "Regexp did not match", "regexp", re, "line", string(data))
			return false, errors.New("regexp did not match")
		}
		probeFailedDueToRegex.Set(0)
	}
	return true, nil
}

func frontVerify(qr config.QueryResponse) bool {
	if qr.Send == "" || qr.Expect == "" {
		return false
	}
	return true
}
