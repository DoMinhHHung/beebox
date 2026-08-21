package smtpdelivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

func (d *Delivery) DeliverSignInLink(ctx context.Context, destination, link string, expiresAt time.Time) error {
	if d == nil || strings.ContainsAny(destination, "\r\n") || strings.ContainsAny(link, "\r\n") {
		return ErrDelivery
	}
	if _, err := mail.ParseAddress(destination); err != nil {
		return ErrDelivery
	}
	parsed, err := url.Parse(link)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Fragment == "" || parsed.Query().Get("challenge") == "" || parsed.Query().Get("pk") == "" {
		return ErrDelivery
	}
	ctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()
	host, _, _ := net.SplitHostPort(d.cfg.Address)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.cfg.Address)
	if err != nil {
		return stableDeliveryError(ctx)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	var client *smtp.Client
	if d.cfg.TLSMode == TLSModeImplicit {
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return stableDeliveryError(ctx)
		}
		client, err = smtp.NewClient(tlsConn, host)
	} else {
		client, err = smtp.NewClient(conn, host)
	}
	if err != nil {
		return stableDeliveryError(ctx)
	}
	defer client.Close()
	if d.cfg.TLSMode == TLSModeSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return ErrDelivery
		}
		if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}); err != nil {
			return stableDeliveryError(ctx)
		}
	}
	if d.cfg.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return ErrDelivery
		}
		if err := client.Auth(smtp.PlainAuth("", d.cfg.Username, d.cfg.Password, host)); err != nil {
			return stableDeliveryError(ctx)
		}
	}
	if err := client.Mail(d.cfg.From); err != nil {
		return stableDeliveryError(ctx)
	}
	if err := client.Rcpt(destination); err != nil {
		return stableDeliveryError(ctx)
	}
	writer, err := client.Data()
	if err != nil {
		return stableDeliveryError(ctx)
	}
	message := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: BeeBox sign-in link\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nOpen this one-time BeeBox sign-in link: %s\r\n\r\nIt expires at %s. If you did not request this sign-in, ignore this message.\r\n",
		d.cfg.From, destination, link, expiresAt.UTC().Format(time.RFC3339),
	)
	buffered := bufio.NewWriter(writer)
	if _, err := buffered.WriteString(message); err != nil {
		_ = writer.Close()
		return stableDeliveryError(ctx)
	}
	if err := buffered.Flush(); err != nil {
		_ = writer.Close()
		return stableDeliveryError(ctx)
	}
	if err := writer.Close(); err != nil {
		return stableDeliveryError(ctx)
	}
	if err := client.Quit(); err != nil {
		return stableDeliveryError(ctx)
	}
	return nil
}
