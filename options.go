/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
*/
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
)

type options struct {
	Address           string
	Port              int
	EnableTLS         bool
	CertFile          string
	KeyFile           string
	CookieSecret      string
	ResourcesBasePath string
	MpinJSURL         string
	ForceActivate     bool
	RPSHost           string
	RPSSchema         string
	CACertFile        string
	RpsPrefix         string
	ClientSettingsURL string
	VerifyIdentityURL string
	RequestOTP        bool
	LDAPVerify        bool
	LDAPVerifyShow    bool
	LDAPServer        string
	LDAPPort          int
	LDAPBindDN        string
	LDAPBindPWD       string
	LDAPBaseDN        string
	LDAPFilter        string
	LDAPUseTLS        bool
	EmailSubject      string
	EmailSender       string
	SMTPServer        string
	SMTPSPort         int
	SMTPSUser         string
	SMTPPassword      string
	SMTPSUseTLS       bool
	MobileSupport     bool
	MobileAppPath     string
	MobileAppFullURL  string
	UseSecureCookie   bool
	StaticPath        string
	TemplatesPath     string
	StaticURLBase     string
	SessionMaxAge     int
}

func getCurrentDir() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return dir
}

var o options

func init() {

	flag.StringVar(&o.Address, "address", "", "IP address to bind")
	flag.IntVar(&o.Port, "port", 8005, "Port for the application to listen")
	flag.StringVar(&o.CertFile, "cert", "/etc/ssl/certs/ssl-cert-snakeoil.pem", "Path to public certificate file")
	flag.StringVar(&o.KeyFile, "key", "/etc/ssl/private/ssl-cert-snakeoil.key", "Path to certificate key file")
	flag.BoolVar(&o.EnableTLS, "s", false, "Enable TLS")
	flag.StringVar(&o.CookieSecret, "cookie-secret", "", "Secret for creating cookies")
	flag.StringVar(&o.ResourcesBasePath, "resources-base", getCurrentDir(), "Base path for static resources - default is dynamic relative to executable")
	flag.StringVar(&o.MpinJSURL, "pinpad-url", "https://mpin.certivox.net/v3/mpin.js", "URL for MPIN pinpad javascript files")
	flag.BoolVar(&o.ForceActivate, "force-activate", false, "Force user activation without sending mail")
	flag.StringVar(&o.RPSHost, "rps-host", "127.0.0.1:8011", "RPS host")
	flag.StringVar(&o.RPSSchema, "rps-schema", "http", "RPS URI schema")
	flag.StringVar(&o.CACertFile, "ca-cert", "", "Path to CA certificates file")
	flag.StringVar(&o.RpsPrefix, "rps-prefix", "rps", "RPS proxy prefix")
	flag.StringVar(&o.ClientSettingsURL, "client-settings-url", "/rps/clientSettings", "Client settings URL")
	flag.StringVar(&o.VerifyIdentityURL, "verify-identity-url", "http://localhost:8005/mpinActivate", "Verify identity URL")
	flag.BoolVar(&o.RequestOTP, "request-otp", false, "Request OTP")
	flag.StringVar(&o.EmailSubject, "email-subject", "M-Pin demo: New user activation", "Email subject")
	flag.StringVar(&o.EmailSender, "email-sender", "", "Email sender")
	flag.BoolVar(&o.LDAPVerify, "ldap-verify", false, "LDAP verify")
	flag.BoolVar(&o.LDAPVerifyShow, "ldap-verify-show", false, "Show LDAP verify error on MPIN client")
	flag.StringVar(&o.LDAPServer, "ldap-server", "", "LDAP server")
	flag.IntVar(&o.LDAPPort, "ldap-port", 389, "LDAP port")
	flag.StringVar(&o.LDAPBindDN, "ldap-dn", "", "LDAP DN")
	flag.StringVar(&o.LDAPBindPWD, "ldap-password", "", "LDAP password")
	flag.StringVar(&o.LDAPBaseDN, "ldap-basedn", "", "LDAP baseDN")
	flag.StringVar(&o.LDAPFilter, "ldap-filter", "(uid=%s)", "LDAP filter")
	flag.BoolVar(&o.LDAPUseTLS, "ldap-use-tls", false, "LDAP use TLS")
	flag.StringVar(&o.SMTPServer, "smtp-server", "", "SMTP server")
	flag.IntVar(&o.SMTPSPort, "smtp-port", 25, "SMTP port")
	flag.StringVar(&o.SMTPSUser, "smtp-user", "", "SMTP user")
	flag.StringVar(&o.SMTPPassword, "smtp-password", "", "SMTP password")
	flag.BoolVar(&o.SMTPSUseTLS, "smtp-use-tls", false, "SMTP use TLS")
	flag.BoolVar(&o.MobileSupport, "mobile-support", true, "Enable mobile support")
	flag.StringVar(&o.MobileAppPath, "mobile-app-path", "/opt/mpin/mpin-3.5/mobile/", "Local system path to mobile app")
	flag.StringVar(&o.MobileAppFullURL, "mobile-app-full-url", "/m/", "Full URL to mobile app")
	flag.BoolVar(&o.UseSecureCookie, "secure-cookie", false, "Use secure cookie for session (works only on encrypted connection)")

	flag.Parse()

	o.StaticPath = filepath.Join(o.ResourcesBasePath, "public")
	o.TemplatesPath = filepath.Join(o.ResourcesBasePath, "templates")
	o.StaticURLBase = "/public/"
	o.SessionMaxAge = 60 * 60 * 4

}

func getOptions() *options {

	return &o
}
