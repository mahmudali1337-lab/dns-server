package main

import (
"log"
"net"
"os"
"os/signal"
"syscall"

"github.com/miekg/dns"
"gopkg.in/yaml.v3"
)

type Config struct {
Listen string `yaml:"listen"`
Zones  []Zone `yaml:"zones"`
}

type Zone struct {
Domain string   `yaml:"domain"`
IP     string   `yaml:"ip"`
TTL    uint32   `yaml:"ttl"`
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

type Sub struct {
Name string `yaml:"name"`
IP   string `yaml:"ip"`
}

var zones []Zone

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
ns   := dns.Fqdn("ns." + zone.Domain)
ns2  := dns.Fqdn("ns2." + zone.Domain)

ttl := zone.TTL
if ttl == 0 {
ttl = 300
}

hdr := func(name string, t uint16) dns.RR_Header {
return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
}

switch q.Name {
case fqdn:
answered = true
switch q.Qtype {
case dns.TypeA:
if ip := safeParseIP(zone.IP); ip != nil {
msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(fqdn, dns.TypeA), A: ip})
}
case dns.TypeNS:
msg.Answer = append(msg.Answer,
&dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: ns},
&dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: ns2},
)
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
Txt: []string{t.Value},
})
}
}
case dns.TypeSOA:
msg.Answer = append(msg.Answer, &dns.SOA{
Hdr:     hdr(fqdn, dns.TypeSOA),
Ns:      ns,
Mbox:    dns.Fqdn("admin." + zone.Domain),
Serial:  2026050302,
Refresh: 3600,
Retry:   900,
Expire:  604800,
Minttl:  300,
})
case dns.TypeANY:
if ip := safeParseIP(zone.IP); ip != nil {
msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(fqdn, dns.TypeA), A: ip})
}
msg.Answer = append(msg.Answer,
&dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: ns},
&dns.NS{Hdr: hdr(fqdn, dns.TypeNS), Ns: ns2},
)
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
Txt: []string{t.Value},
})
}
}
}

case ns:
answered = true
if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
if ip := safeParseIP(zone.IP); ip != nil {
msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(ns, dns.TypeA), A: ip})
}
}

case ns2:
answered = true
if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
if ip := safeParseIP(zone.IP); ip != nil {
msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr(ns2, dns.TypeA), A: ip})
}
}

default:
for _, sub := range zone.Subs {
subFqdn := dns.Fqdn(sub.Name + "." + zone.Domain)
if subFqdn != q.Name {
continue
}
answered = true
if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
if ip := safeParseIP(sub.IP); ip != nil {
msg.Answer = append(msg.Answer, &dns.A{
Hdr: hdr(subFqdn, dns.TypeA),
A:   ip,
})
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
Txt: []string{t.Value},
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

go func() {
if err := udp.ListenAndServe(); err != nil {
log.Fatalf("UDP: %v", err)
}
}()
go func() {
if err := tcp.ListenAndServe(); err != nil {
log.Fatalf("TCP: %v", err)
}
}()

log.Printf("DNS listening on %s", cfg.Listen)

sig := make(chan os.Signal, 1)
signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
<-sig

_ = udp.Shutdown()
_ = tcp.Shutdown()
}