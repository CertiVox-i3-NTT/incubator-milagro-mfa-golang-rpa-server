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
	"bytes"
	"fmt"
	"net/smtp"
)

var htmlBody = `<html>
<head></head>
<body>
<p><b>Activation</b></p>
<p>Your identity is now ready to activate:</p>
<p><a href="%v" target="_blank">Click this activation link and follow the instructions</a></p>
<p>Regards,<br/>
The Milagro MFA Team</p>
</body>
</html>`

func sendMail(userID string, body *bytes.Buffer, o *options) (err error) {

	auth := smtp.PlainAuth(
		"",
		o.SMTPSUser,
		o.SMTPPassword,
		o.SMTPServer,
	)

	if o.SMTPPassword == ""{
		auth = nil
	}

	return smtp.SendMail(
		fmt.Sprintf("%v:%v", o.SMTPServer, o.SMTPSPort),
		auth,
		o.EmailSender,
		[]string{userID},
		body.Bytes(),
	)
}


func sendActivationMail(userID, deviceName, validateURL string, o *options) (err error) {

	body := bytes.NewBuffer(nil)

	var writeBodyFmt = func(format string, vars ...interface{}) {
		body.WriteString(fmt.Sprintf(format+"\r\n", vars...))
	}

//	boundary := "boundary5362167"

//	writeBodyFmt(`Content-Type: multipart/alternative; boundary="%v"`, boundary)
//	writeBodyFmt("MIME-Version: 1.0 ")

	writeBodyFmt("From: %v", o.EmailSender)
	writeBodyFmt("To: %v", userID)
	writeBodyFmt("Subject: %v", o.EmailSubject)

//	writeBodyFmt("--%v", boundary)
//	writeBodyFmt(`Content-Type: text/plain; charset="utf-8"`)
//	writeBodyFmt("MIME-Version: 1.0 ")
//	writeBodyFmt("Content-Transfer-Encoding: 7bit")

	writeBodyFmt("")
	writeBodyFmt("Your identity is now ready to activate:")
	writeBodyFmt("Click this activation link and follow the instructions:")
	writeBodyFmt("%v", validateURL)
	writeBodyFmt("")
	writeBodyFmt("Regards,")
	writeBodyFmt("The Milagro MFA Team")

//	writeBodyFmt("--%v", boundary)
//	writeBodyFmt(`Content-Type: text/html; charset="utf-8"`)
//	writeBodyFmt("MIME-Version: 1.0 ")
//	writeBodyFmt("Content-Transfer-Encoding: 7bit")
//	writeBodyFmt(htmlBody, validateURL)

//	writeBodyFmt("--%v--", boundary)

	return sendMail(userID, body, o)
}


func sendEMpinActivationMail(userID, deviceName string, activationCode int, o *options) (err error) {

	body := bytes.NewBuffer(nil)

	var writeBodyFmt = func(format string, vars ...interface{}) {
		body.WriteString(fmt.Sprintf(format+"\r\n", vars...))
	}

	ac3 := activationCode % 10000
	ac2 := activationCode / 10000 % 10000
	ac1 := activationCode / (10000 * 10000)
	activationCodeStr := fmt.Sprintf("%04d-%04d-%04d", ac1, ac2, ac3)

//	boundary := "boundary5362167"

//	writeBodyFmt(`Content-Type: multipart/alternative; boundary="%v"`, boundary)
//	writeBodyFmt("MIME-Version: 1.0 ")

	writeBodyFmt("From: %v", o.EmailSender)
	writeBodyFmt("To: %v", userID)
	writeBodyFmt("Subject: %v", o.EmailSubject)

//	writeBodyFmt("--%v", boundary)
//	writeBodyFmt(`Content-Type: text/plain; charset="utf-8"`)
//	writeBodyFmt("MIME-Version: 1.0 ")
//	writeBodyFmt("Content-Transfer-Encoding: 7bit")
	writeBodyFmt("")
	writeBodyFmt("Your Activation code is")
	writeBodyFmt("%v", activationCodeStr)
	writeBodyFmt("")
	writeBodyFmt("Regards,")
	writeBodyFmt("The Milagro MFA Team")

	return sendMail(userID, body, o)
}
