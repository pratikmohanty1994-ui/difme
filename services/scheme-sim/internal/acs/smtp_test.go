package acs_test

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/pratikmohanty1294/difme/services/scheme-sim/internal/acs"
)

type mail struct{ to, data string }

// smtpSink is a minimal SMTP server (the part Mailpit plays on the cluster): it records each message.
func smtpSink(t *testing.T) (string, chan mail) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan mail, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r, w := bufio.NewReader(c), bufio.NewWriter(c)
				say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
				say("220 sink")
				var m mail
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
						say("250 sink")
					case strings.HasPrefix(cmd, "RCPT TO:"):
						m.to = strings.Trim(strings.TrimSpace(line)[8:], "<>")
						say("250 ok")
					case cmd == "DATA":
						say("354 go")
						var b strings.Builder
						for {
							l, err := r.ReadString('\n')
							if err != nil || strings.TrimSpace(l) == "." {
								break
							}
							b.WriteString(l)
						}
						m.data = b.String()
						got <- m
						say("250 queued")
					case cmd == "QUIT":
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}(c)
		}
	}()
	return l.Addr().String(), got
}

func TestSMTPSenderDeliversPasscodes(t *testing.T) {
	addr, got := smtpSink(t)
	s := acs.SMTPSender{Addr: addr, From: "3ds@difme.local", SMSDomain: "sms.difme.local"}
	card := acs.Card{Email: "holder@example.org", Mobile: "+919800000001", Channels: []string{"sms", "email"}}
	ctx := context.Background()
	if err := s.Send(ctx, "4375510000000001", card, "email", "482913"); err != nil {
		t.Fatal(err)
	}
	m := <-got
	if m.to != "holder@example.org" || !strings.Contains(m.data, "482913") || !strings.Contains(m.data, "ending 0001") || strings.Contains(m.data, "437551") {
		t.Fatalf("email: %+v", m)
	}
	if err := s.Send(ctx, "4375510000000001", card, "sms", "119922"); err != nil {
		t.Fatal(err)
	}
	if m := <-got; m.to != "+919800000001@sms.difme.local" || !strings.Contains(m.data, "119922") {
		t.Fatalf("sms: %+v", m)
	}
	if err := s.Send(ctx, "4375510000000001", acs.Card{}, "email", "1"); err == nil {
		t.Fatal("no address: sent anyway")
	}
	if err := s.Send(ctx, "4375510000000001", acs.Card{Email: "a@b\r\nBcc: x@y"}, "email", "1"); err == nil {
		t.Fatal("header injection accepted")
	}
}
