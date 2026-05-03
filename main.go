package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen string `yaml:"listen"`
	Zones  []Zone `yaml:"zones"`
}

type Zone struct {
	Domain string   `yaml:"domain"`
	IP     string   `yaml:"ip"`  // backward compat: single IP
	IPs    []string `yaml:"ips"` // multiple IPs for round-robin
	TTL    uint32   `yaml:"ttl"`
	NS     []NSRec  `yaml:"ns"`
	MX     []MXRec  `yaml:"mx"`
	TXT    []TXTRec `yaml:"txt"`
	Subs   []Sub    `yaml:"subs"`
}

type MXRec struct {
	Priority uint16 `yaml:"priority"`
	Host     string `yaml:"host"`
}

type TXTRec struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

type NSRec struct {
	Name string `yaml:"name"`
	IP   string `yaml:"ip"`
}

type Sub struct {
	Name string   `yaml:"name"`
	IP   string   `yaml:"ip"`  // backward compat: single IP
	IPs  []string `yaml:"ips"` // multiple IPs for round-robin
}

var zones []Zone

// allIPs merges the legacy single-IP field with the new multi-IP list.
// The single IP comes first and duplicates are skipped.
func allIPs(ip string, ips []string) []string {
	seen := map[string]bool{}
	var out []string
	if ip != "" {
		seen[ip] = true
		out = append(out, ip)
	}
	for _, i := range ips {
		if i != "" && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	return out
}

func soaSerial() uint32 {
	t := time.Now().UTC()
	return uint32(t.Year()*1000000 + int(t.Month())*10000 + t.Day()*100)
}

func splitTXT(s string) []string {
	var chunks []string
	for len(s) > 255 {
		chunks = append(chunks, s[:255])
		s = s[255:]
	}
	chunks = append(chunks, s)
	return chunks
}

func safeParseIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("panic in handler: %v", rec)
		}
	}()

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		answered := false

		for _, zone := range zones {
			fqdn := dns.Fqdn(zone.Domain)

			ttl := zone.TTL
			if ttl == 0 {
				ttl = 300
			}

			hdr := func(name string, t uint16) dns.RR_Header {
				return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
			}

			type nsEntry struct{ fqdn, ip string }
			var nsEntries []nsEntry
			if len(zone.NS) > 0 {
				for _, n := range zone.NS {
					nsEntries = append(nsEntries, nsEntry{dns.Fqdn(n.Name + "." + zone.Domain), n.IP})
				}
			} else {
				ip0 := ""
				if first := allIPs(zone.IP, zone.IPs); len(first) > 0 {
					ip0 = first[0]
				}
				nsEntries = []nsEntry{
					{dns.Fqdn("ns." + zone.Domain), ip0},
					{dns.Fqdn("ns2." + zone.Domain), ip0},
				}
			}
			primaryNS := nsEntries[0].fqdn
			nsFqdnIP := map[string]string{}
			for _, n := range nsEntries {
				nsFqdnIP[n.fqdn] = n.ip
			}

			switch q.Name {
			case fqdn:
				answered = true
				switch q.Qtype {
				case dns.TypeA:
					for _, raw := range allIPs(zone.IP, zone.IPs) {
						if ip := safeParseIP(raw); ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(fqdn, dns.TypeA), A: ip})
						}
					}
				case dns.TypeNS:
					for _, n := range nsEntries {
						msg.Answer = append(msg.Answer, &dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: n.fqdn})
					}
				case dns.TypeMX:
					for _, mx := range zone.MX {
						msg.Answer = append(msg.Answer, &dns.MX{
							Hdr:        hdr(fqdn, dns.TypeMX),
							Preference: mx.Priority,
							Mx:         dns.Fqdn(mx.Host),
						})
					}
				case dns.TypeTXT:
					for _, t := range zone.TXT {
						if t.Name == "@" || t.Name == "" {
							msg.Answer = append(msg.Answer, &dns.TXT{
								Hdr: hdr(fqdn, dns.TypeTXT),
								Txt: splitTXT(t.Value),
							})
						}
					}
				case dns.TypeSOA:
					msg.Answer = append(msg.Answer, &dns.SOA{
						Hdr:     hdr(fqdn, dns.TypeSOA),
						Ns:      primaryNS,
						Mbox:    dns.Fqdn("admin." + zone.Domain),
						Serial:  soaSerial(),
						Refresh: 3600,
						Retry:   900,
						Expire:  604800,
						Minttl:  300,
					})
				case dns.TypeANY:
					for _, raw := range allIPs(zone.IP, zone.IPs) {
						if ip := safeParseIP(raw); ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(fqdn, dns.TypeA), A: ip})
						}
					}
					for _, n := range nsEntries {
						msg.Answer = append(msg.Answer, &dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: n.fqdn})
					}
					for _, mx := range zone.MX {
						msg.Answer = append(msg.Answer, &dns.MX{
							Hdr:        hdr(fqdn, dns.TypeMX),
							Preference: mx.Priority,
							Mx:         dns.Fqdn(mx.Host),
						})
					}
					for _, t := range zone.TXT {
						if t.Name == "@" || t.Name == "" {
							msg.Answer = append(msg.Answer, &dns.TXT{
								Hdr: hdr(fqdn, dns.TypeTXT),
								Txt: splitTXT(t.Value),
							})
						}
					}
				}

			default:
				if nsIP, ok := nsFqdnIP[q.Name]; ok {
					answered = true
					if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
						if ip := safeParseIP(nsIP); ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(q.Name, dns.TypeA), A: ip})
						}
					}
					break
				}
				for _, sub := range zone.Subs {
					subFqdn := dns.Fqdn(sub.Name + "." + zone.Domain)
					if subFqdn != q.Name {
						continue
					}
					answered = true
					if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
						for _, raw := range allIPs(sub.IP, sub.IPs) {
							if ip := safeParseIP(raw); ip != nil {
								msg.Answer = append(msg.Answer, &dns.A{
									Hdr: hdr(subFqdn, dns.TypeA),
									A:   ip,
								})
							}
						}
					}
					break
				}
				if !answered {
					for _, t := range zone.TXT {
						if t.Name == "" || t.Name == "@" {
							continue
						}
						txtFqdn := dns.Fqdn(t.Name + "." + zone.Domain)
						if txtFqdn == q.Name && (q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY) {
							answered = true
							msg.Answer = append(msg.Answer, &dns.TXT{
								Hdr: hdr(q.Name, dns.TypeTXT),
								Txt: splitTXT(t.Value),
							})
						}
					}
				}
			}

			if answered {
				break
			}
		}

		if !answered {
			msg.SetRcode(r, dns.RcodeNameError)
			// RFC 2308: add SOA in authority section for NXDOMAIN so resolvers can cache negative responses
			for _, zone := range zones {
				if dns.IsSubDomain(dns.Fqdn(zone.Domain), q.Name) {
					ttl := zone.TTL
					if ttl == 0 {
						ttl = 300
					}
					zoneNS := dns.Fqdn("ns." + zone.Domain)
					if len(zone.NS) > 0 {
						zoneNS = dns.Fqdn(zone.NS[0].Name + "." + zone.Domain)
					}
					msg.Ns = append(msg.Ns, &dns.SOA{
						Hdr:     dns.RR_Header{Name: dns.Fqdn(zone.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
						Ns:      zoneNS,
						Mbox:    dns.Fqdn("admin." + zone.Domain),
						Serial:  soaSerial(),
						Refresh: 3600,
						Retry:   900,
						Expire:  604800,
						Minttl:  ttl,
					})
					break
				}
			}
		} else if len(msg.Answer) == 0 {
			// RFC 2308: NODATA — name exists but no records of this type; add SOA to authority
			for _, zone := range zones {
				if dns.IsSubDomain(dns.Fqdn(zone.Domain), q.Name) || dns.Fqdn(zone.Domain) == q.Name {
					ttl := zone.TTL
					if ttl == 0 {
						ttl = 300
					}
					zoneNS := dns.Fqdn("ns." + zone.Domain)
					if len(zone.NS) > 0 {
						zoneNS = dns.Fqdn(zone.NS[0].Name + "." + zone.Domain)
					}
					msg.Ns = append(msg.Ns, &dns.SOA{
						Hdr:     dns.RR_Header{Name: dns.Fqdn(zone.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
						Ns:      zoneNS,
						Mbox:    dns.Fqdn("admin." + zone.Domain),
						Serial:  soaSerial(),
						Refresh: 3600,
						Retry:   900,
						Expire:  604800,
						Minttl:  ttl,
					})
					break
				}
			}
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("write error: %v", err)
	}
}

func main() {
	path := "config.yaml"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read config: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = ":53"
	}

	zones = cfg.Zones
	log.Printf("loaded %d zone(s)", len(zones))

	dns.HandleFunc(".", handle)

	udp := &dns.Server{Addr: cfg.Listen, Net: "udp"}
	tcp := &dns.Server{Addr: cfg.Listen, Net: "tcp"}

	// Use an error channel so that a ListenAndServe failure is logged and causes
	// a clean exit (instead of log.Fatalf inside a goroutine which could race
	// against the logger and produce no output before os.Exit).
	errc := make(chan error, 2)
	go func() {
		if err := udp.ListenAndServe(); err != nil {
			errc <- fmt.Errorf("UDP: %w", err)
		}
	}()
	go func() {
		if err := tcp.ListenAndServe(); err != nil {
			errc <- fmt.Errorf("TCP: %w", err)
		}
	}()

	log.Printf("DNS listening on %s", cfg.Listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errc:
		log.Fatalf("server error: %v", err)
	case <-sig:
	}

	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}
