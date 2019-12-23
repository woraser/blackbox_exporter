package prober

import (
	"bufio"
	"context"
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
	fmt.Println("sourceAddr:", sourceAddr)
	level.Info(logger).Log("msg", "Dialing UDP")
	return net.DialUDP(dialProtocol, nil, addr)
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

	scanner := bufio.NewScanner(conn)
	for i, qr := range module.UDP.QueryResponse {
		level.Info(logger).Log("msg", "Processing query response entry", "entry_number", i)
		send := qr.Send
		if qr.Expect != "" {
			re, err := regexp.Compile(qr.Expect)
			if err != nil {
				level.Error(logger).Log("msg", "Could not compile into regular expression", "regexp", qr.Expect, "err", err)
				return false
			}
			var match []int
			// Read lines until one of them matches the configured regexp.
			for scanner.Scan() {
				level.Debug(logger).Log("msg", "Read line", "line", scanner.Text())
				match = re.FindSubmatchIndex(scanner.Bytes())
				if match != nil {
					level.Info(logger).Log("msg", "Regexp matched", "regexp", re, "line", scanner.Text())
					break
				}
			}
			if scanner.Err() != nil {
				level.Error(logger).Log("msg", "Error reading from connection", "err", scanner.Err().Error())
				return false
			}
			if match == nil {
				probeFailedDueToRegex.Set(1)
				level.Error(logger).Log("msg", "Regexp did not match", "regexp", re, "line", scanner.Text())
				return false
			}
			probeFailedDueToRegex.Set(0)
			send = string(re.Expand(nil, []byte(send), scanner.Bytes(), match))
		}
		if send != "" {
			level.Debug(logger).Log("msg", "Sending line", "line", send)
			if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
				level.Error(logger).Log("msg", "Failed to send", "err", err)
				return false
			}
		}
	}
	return true
}
