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
	"testing"
)

func TestGetCurrentDir(t *testing.T) {
	dir := getCurrentDir()
	if dir == "" {
		t.Error("cannot get current directory")
	}
}

func TestInit(t *testing.T) {
	address := ""
	port := 8005
	enableTLS := false
	certFile := "/etc/ssl/certs/ssl-cert-snakeoil.pem"
	keyFile := "/etc/ssl/private/ssl-cert-snakeoil.key"
	cookieSecret := ""
	mpinJSURL := "https://mpin.certivox.net/v3/mpin.js"
	forceActivate := false
	rpsHost := "127.0.0.1:8011"
	rpsSchema := "http"
	caCertFile := ""
	rpsPrefix := "rps"
	clientSettingsURL := "/rps/clientSettings"
	verifyIdentityURL := "http://localhost:8005/mpinActivate"
	requestOTP := false
	ldapVerify := false
	ldapVerifyShow := false
	ldapServer := ""
	ldapPort := 389
	ldapBindDN := ""
	ldapBindPWD := ""
	ldapBaseDN := ""
	ldapFilter := "(uid=%s)"
	ldapUseTLS := false
	emailSubject := "M-Pin demo: New user activation"
	emailSender := ""
	smtpServer := ""
	smtpsPort := 25
	smtpsUser := ""
	smtpPassword := ""
	smtpsUseTLS := false
	mobileSupport := true
	mobileAppPath := "/opt/mpin/mpin-3.5/mobile/"
	mobileAppFullURL := "/m/"
	useSecureCookie := false
	staticPath := o.ResourcesBasePath + "/public"
	templatesPath := o.ResourcesBasePath + "/templates"
	staticURLBase := "/public/"
	sessionMaxAge := 60 * 60 * 4

	if o.Address != address {
		t.Errorf("options.Addres = <%s> want <%s>", o.Address, address)
	}
	if o.Port != port {
		t.Errorf("options.Addres = <%d> want <%d>", o.Address, port)
	}
	if o.EnableTLS != enableTLS {
		t.Errorf("options.EnableTLS = <%t> want <%t>", o.EnableTLS, enableTLS)
	}
	if o.CertFile != certFile {
		t.Errorf("options.CertFile = <%s> want <%s>", o.CertFile, certFile)
	}
	if o.KeyFile != keyFile {
		t.Errorf("options.KeyFile = <%s> want <%s>", o.KeyFile, keyFile)
	}
	if o.CookieSecret != cookieSecret {
		t.Errorf("options.CookieSecret = <%s> want <%s>", o.CookieSecret, cookieSecret)
	}
	if o.ResourcesBasePath == "" {
		t.Error("options.ResourcesBasePath is empty")
	}
	if o.MpinJSURL != mpinJSURL {
		t.Errorf("options.MpinJSURL = <%s> want <%s>", o.MpinJSURL, mpinJSURL)
	}
	if o.ForceActivate != forceActivate {
		t.Errorf("options.ForceActivate = <%t> want <%t>", o.ForceActivate, forceActivate)
	}
	if o.RPSHost != rpsHost {
		t.Errorf("options.RPSHost = <%s> want <%s>", o.RPSHost, rpsHost)
	}
	if o.RPSSchema != rpsSchema {
		t.Errorf("options.RPSSchema = <%s> want <%s>", o.RPSSchema, rpsSchema)
	}
	if o.CACertFile != caCertFile {
		t.Errorf("options.CACertFile = <%s> want <%s>", o.CACertFile, caCertFile)
	}
	if o.RpsPrefix != rpsPrefix {
		t.Errorf("options.RpsPrefix = <%s> want <%s>", o.RpsPrefix, rpsPrefix)
	}
	if o.ClientSettingsURL != clientSettingsURL {
		t.Errorf("options.ClientSettingsURL = <%s> want <%s>", o.ClientSettingsURL, clientSettingsURL)
	}
	if o.VerifyIdentityURL != verifyIdentityURL {
		t.Errorf("options.VerifyIdentityURL = <%s> want <%s>", o.VerifyIdentityURL, verifyIdentityURL)
	}
	if o.RequestOTP != requestOTP {
		t.Errorf("options.RequestOTP = <%t> want <%t>", o.RequestOTP, requestOTP)
	}
	if o.LDAPVerify != ldapVerify {
		t.Errorf("options.LDAPVerify = <%t> want <%t>", o.LDAPVerify, ldapVerify)
	}
	if o.LDAPVerifyShow != ldapVerifyShow {
		t.Errorf("options.LDAPVerifyShow = <%t> want <%t>", o.LDAPVerify, ldapVerifyShow)
	}
	if o.LDAPServer != ldapServer {
		t.Errorf("options.LDAPServer = <%s> want <%s>", o.LDAPServer, ldapServer)
	}
	if o.LDAPPort != ldapPort {
		t.Errorf("options.LDAPPort = <%d> want <%d>", o.LDAPPort, ldapPort)
	}
	if o.LDAPBindDN != ldapBindDN {
		t.Errorf("options.LDAPBindDN = <%s> want <%s>", o.LDAPBindDN, ldapBindDN)
	}
	if o.LDAPBindPWD != ldapBindPWD {
		t.Errorf("options.LDAPBindPWD = <%s> want <%s>", o.LDAPBindPWD, ldapBindPWD)
	}
	if o.LDAPBaseDN != ldapBaseDN {
		t.Errorf("options.LDAPBaseDN = <%s> want <%s>", o.LDAPBaseDN, ldapBaseDN)
	}
	if o.LDAPFilter != ldapFilter {
		t.Errorf("options.LDAPFilter = <%s> want <%s>", o.LDAPFilter, ldapFilter)
	}
	if o.LDAPUseTLS != ldapUseTLS {
		t.Errorf("options.LDAPUseTLS = <%t> want <%t>", o.LDAPUseTLS, ldapUseTLS)
	}
	if o.EmailSubject != emailSubject {
		t.Errorf("options.EmailSubject = <%s> want <%s>", o.EmailSubject, emailSubject)
	}
	if o.EmailSender != emailSender {
		t.Errorf("options.EmailSender = <%s> want <%s>", o.EmailSender, emailSender)
	}
	if o.SMTPServer != smtpServer {
		t.Errorf("options.SMTPServer = <%s> want <%s>", o.SMTPServer, smtpServer)
	}
	if o.SMTPSPort != smtpsPort {
		t.Errorf("options.SMTPSPort = <%d> want <%d>", o.SMTPSPort, smtpsPort)
	}
	if o.SMTPSUser != smtpsUser {
		t.Errorf("options.SMTPSUser = <%s> want <%s>", o.SMTPSUser, smtpsUser)
	}
	if o.SMTPPassword != smtpPassword {
		t.Errorf("options.SMTPPassword = <%s> want <%s>", o.SMTPPassword, smtpPassword)
	}
	if o.SMTPSUseTLS != smtpsUseTLS {
		t.Errorf("options.SMTPSUseTLS = <%t> want <%t>", o.SMTPSUseTLS, smtpsUseTLS)
	}
	if o.MobileSupport != mobileSupport {
		t.Errorf("options.MobileSupport = <%t> want <%t>", o.MobileSupport, mobileSupport)
	}
	if o.MobileAppPath != mobileAppPath {
		t.Errorf("options.MobileAppPath = <%s> want <%s>", o.MobileAppPath, mobileAppPath)
	}
	if o.MobileAppFullURL != mobileAppFullURL {
		t.Errorf("options.MobileAppFullURL = <%s> want <%s>", o.MobileAppFullURL, mobileAppFullURL)
	}
	if o.UseSecureCookie != useSecureCookie {
		t.Errorf("options.UseSecureCookie = <%t> want <%t>", o.UseSecureCookie, useSecureCookie)
	}
	if o.StaticPath != staticPath {
		t.Errorf("options.StaticPath = <%s> want <%s>", o.StaticPath, staticPath)
	}
	if o.TemplatesPath != templatesPath {
		t.Errorf("options.TemplatesPath = <%s> want <%s>", o.TemplatesPath, templatesPath)
	}
	if o.StaticURLBase != staticURLBase {
		t.Errorf("options.StaticURLBase = <%s> want <%s>", o.StaticURLBase, staticURLBase)
	}
	if o.SessionMaxAge != sessionMaxAge {
		t.Errorf("options.SessionMaxAge = <%d> want <%d>", o.SessionMaxAge, sessionMaxAge)
	}
}

func TestGetOptions(t *testing.T) {
	opt := getOptions()
	if *opt != o {
		t.Error("cannot get options")
	}
}
