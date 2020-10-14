// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/woraser/blackbox_exporter/config"
	"gopkg.in/yaml.v3"
)

func dialUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (net.Conn, error) {
	var dialProtocol string
	sourceAddr := &net.UDPAddr{}
	targetAddress, port, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Error splitting target address and port", "err", err)
		return nil, err
	}
	udpConfig := module.UDP

	// select ip protocol for udp
	// default IPProtocol: ipv4
	// chooseProtocol return err if module.UDP.IPProtocol is empty
	// TODO lost ipv6 test
	if udpConfig.IPProtocol == "" {
		udpConfig.IPProtocol = "ip4"
	}
	ip, _, err := chooseProtocol(ctx, udpConfig.IPProtocol, udpConfig.IPProtocolFallback, targetAddress, registry, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return nil, err
	}

	if ip.IP.To4() == nil {
		dialProtocol = "udp6"
	} else {
		dialProtocol = "udp4"
	}

	if len(udpConfig.SourceIPAddress) > 0 {
		srcIP := net.ParseIP(udpConfig.SourceIPAddress)
		if srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", udpConfig.SourceIPAddress)
			return nil, fmt.Errorf("error parsing source ip address: %s", udpConfig.SourceIPAddress)
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

func ProbeUDP(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger, params url.Values) bool {
	probeFailedDueToRegex := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_regex",
		Help: "Indicates if probe failed due to regex",
	})
	registry.MustRegister(probeFailedDueToRegex)
	//parse param if exists
	config := params.Get("config")
	if config != "" {
		b, err := base64.StdEncoding.DecodeString(config)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to decode udp config", "err", err)
			return false
		}
		err = yaml.Unmarshal(b, &module.UDP)
		if err != nil {
			level.Error(logger).Log("msg", "Failed to unmarshal udp config", "err", err)
			return false
		}
	}

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
	// use default deadline:3s
	if err := conn.SetDeadline(time.Now().Add(time.Second * 3)); err != nil {
		level.Error(logger).Log("msg", "Error setting deadline", "err", err)
		return false
	}

	if len(module.UDP.QueryResponse) == 0 {
		_, er := verifyConnect(logger, conn)
		if er != nil {
			level.Error(logger).Log("msg", "failed verifyQueryResponse", er)
			return false
		}
	} else {
		scanner := bufio.NewScanner(conn)
		for i, qr := range module.UDP.QueryResponse {
			level.Info(logger).Log("msg", "Processing query response entry", "entry_number", i)
			send := qr.Send
			if send != "" {
				level.Debug(logger).Log("msg", "Sending line", "line", send)
				if _, err := fmt.Fprintf(conn, "%s\n", send); err != nil {
					level.Error(logger).Log("msg", "Failed to send", "err", err)
					return false
				}
			}
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
			}
		}
	}

	return true
}

func verifyConnect(logger log.Logger, conn net.Conn) (bool, error) {
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
