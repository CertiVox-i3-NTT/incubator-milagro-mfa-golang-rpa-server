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
	"fmt"
	"io/ioutil"
	"os/user"
	"strings"
	"testing"
	"time"
)

var smtpHost = "127.0.0.1"
var smtpPort = 25
var smtpSubmissionPort = 587
var mailDir = "/var/mail"
var smtpPassword = "password"

func TestSendActivationMail(t *testing.T) {
	mailSubject := "emailSubject"
	validateURL := "http://localhost/"
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: "", SMTPPassword: "", SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: smtpPort}

	err = sendActivationMail(mailAddress, "", validateURL, &o)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1000 * time.Millisecond)

	contentBytes, err := ioutil.ReadFile(mailDir + "/" + user.Username)
	if err != nil {
		t.Error(err)
	}
	content := string(contentBytes)
	lastIndex := strings.LastIndex(content, "From ")
	if lastIndex == -1 {
		t.Error("mail not found")
	}

	header := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\n", mailAddress, mailAddress, mailSubject)
	if strings.Index(content[lastIndex:], header) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], header)
	}

	body :=
`Your identity is now ready to activate:
Click this activation link and follow the instructions:
http://localhost/

Regards,
The Milagro MFA Team`
	if strings.Index(content[lastIndex:], body) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], body)
	}
}

func TestSendActivationMailSeindError(t *testing.T) {
	mailSubject := "emailSubject"
	validateURL := "http://localhost/"
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: "", SMTPPassword: "", SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: 65536}

	err = sendActivationMail(mailAddress, "", validateURL, &o)
	errMessage := "dial tcp: invalid port 65536"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

/*
func TestSendActivationMailAuth(t *testing.T) {
	mailSubject := "emailSubject"
	validateURL := "http://localhost/"
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: user.Username, SMTPPassword: smtpPassword, SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: smtpSubmissionPort}

	err = sendActivationMail(mailAddress, "", validateURL, &o)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1000 * time.Millisecond)

	contentBytes, err := ioutil.ReadFile(mailDir + "/" + user.Username)
	if err != nil {
		t.Error(err)
	}
	content := string(contentBytes)
	lastIndex := strings.LastIndex(content, "From ")
	if lastIndex == -1 {
		t.Error("mail not found")
	}

	header := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\n", mailAddress, mailAddress, mailSubject)
	if strings.Index(content[lastIndex:], header) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], header)
	}

	body :=
`Your identity is now ready to activate:
Click this activation link and follow the instructions:
http://localhost/

Regards,
The Milagro MFA Team`
	if strings.Index(content[lastIndex:], body) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], body)
	}
}
*/

func TestSendEMpinActivationMail(t *testing.T) {
	mailSubject := "emailSubject"
	activateCode := 123456789012
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: "", SMTPPassword: "", SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: smtpPort}

	err = sendEMpinActivationMail(mailAddress, "", activateCode, &o)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1000 * time.Millisecond)

	contentBytes, err := ioutil.ReadFile(mailDir + "/" + user.Username)
	if err != nil {
		t.Error(err)
	}
	content := string(contentBytes)
	lastIndex := strings.LastIndex(content, "From ")
	if lastIndex == -1 {
		t.Error("mail not found")
	}

	header := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\n", mailAddress, mailAddress, mailSubject)
	if strings.Index(content[lastIndex:], header) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], header)
	}

	body :=
`Your Activation code is
1234-5678-9012

Regards,
The Milagro MFA Team`
	if strings.Index(content[lastIndex:], body) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], body)
	}
}

func TestSendEMpinActivationMailSendError(t *testing.T) {
	mailSubject := "emailSubject"
	activateCode := 123456789012
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: "", SMTPPassword: "", SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: 65536}

	err = sendEMpinActivationMail(mailAddress, "", activateCode, &o)
	errMessage := "dial tcp: invalid port 65536"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

/*
func TestSendEMpinActivationMailAuth(t *testing.T) {
	mailSubject := "emailSubject"
	activateCode := 123456789012
	user, err := user.Current()
	if err != nil {
		t.Error(err)
	}
	mailAddress := user.Username + "@localhost.localdomain"

	o := options{SMTPSUser: user.Username, SMTPPassword: smtpPassword, SMTPServer: smtpHost, EmailSender: mailAddress, EmailSubject: mailSubject, SMTPSPort: smtpSubmissionPort}

	err = sendEMpinActivationMail(mailAddress, "", activateCode, &o)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(1000 * time.Millisecond)

	contentBytes, err := ioutil.ReadFile(mailDir + "/" + user.Username)
	if err != nil {
		t.Error(err)
	}
	content := string(contentBytes)
	lastIndex := strings.LastIndex(content, "From ")
	if lastIndex == -1 {
		t.Error("mail not found")
	}

	header := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\n", mailAddress, mailAddress, mailSubject)
	if strings.Index(content[lastIndex:], header) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], header)
	}

	body :=
`Your Activation code is
1234-5678-9012

Regards,
The Milagro MFA Team`
	if strings.Index(content[lastIndex:], body) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], body)
	}
}
*/
