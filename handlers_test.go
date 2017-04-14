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
	"errors"
	"encoding/json"
	"fmt"
	"io"
	"./ldap"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"io/ioutil"
	"os/user"
	"strings"
)

var listenString = "127.0.0.1:10389"
var timeout = 1500 * time.Millisecond
var wait = 2000 * time.Millisecond

func testApp() *app {
	a := newApp()
	a.Fetch = func(a *app, url string, method string, q interface{}, d interface{}) (err error) { return }
	a.Mail = func(userID, deviceName, validateURL string, o *options) (err error) { return }
	a.Authenticate = func(*context, string) (a, b string, c int) { return }
	a.LoginResult = func(*context, string, string, int, string) (err error) { return }
	a.ActivateUser = func(*context, string, string) (err error) { return }
	return a
}

func prepare(method, path string, body io.Reader) (*context, *httptest.ResponseRecorder, *http.Request) {
	c := context{App: testApp()}
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(method, path, body)
	return &c, w, r
}

func TestBaseHandler(t *testing.T) {
	c, w, r := prepare("GET", "/", new(bytes.Buffer))
	baseHandler(c, w, r)
	if w.HeaderMap["Access-Control-Allow-Origin"][0] == "*" {
		t.Log("Header set correctly")
		return
	}
	t.Fail()
}

func validateSetCookie(t *testing.T, c *context, w *httptest.ResponseRecorder, value string, user string) {

	rs := http.Response{Header: w.Header()}

	for _, cookie := range rs.Cookies() {

		if cookie.Name == "mpindemo_session" {

			item, err := c.App.Store.Get(cookie.Value)
			if err != nil {
				t.Fatal("Session missing in storage")
			}

			if ((cookie.Value == value) != (value == "")) &&
				cookie.MaxAge == c.App.Options.SessionMaxAge &&
				item.User == user &&
				item.Expires.After(time.Now()) {
				t.Log("Expected cookie successfully set")
				return
			}
		}
	}
	t.Fatalf("Session not set correctly in cookie, %+v", w.HeaderMap["Set-Cookie"])
}

func TestSessionHandlerNewSession(t *testing.T) {
	c, w, r := prepare("GET", "/", new(bytes.Buffer))
	sessionHandler(c, w, r)
	validateSetCookie(t, c, w, "", "")
}

func TestSessionHandlerMissingSession(t *testing.T) {
	c, w, r := prepare("GET", "/", new(bytes.Buffer))

	cookie := http.Cookie{
		Name:  "mpindemo_session",
		Value: "123"}

	r.AddCookie(&cookie)

	sessionHandler(c, w, r)

	validateSetCookie(t, c, w, "", "")
}

func TestSessionHandlerExpiredSession(t *testing.T) {
	c, w, r := prepare("GET", "/", new(bytes.Buffer))

	cookie := http.Cookie{
		Name:  "mpindemo_session",
		Value: "123"}

	c.App.Store.Put(cookie.Value, session{Expires: time.Now(), User: "foo"})

	r.AddCookie(&cookie)

	sessionHandler(c, w, r)

	validateSetCookie(t, c, w, "", "")
}

func TestSessionHandlerValidSession(t *testing.T) {
	c, w, r := prepare("GET", "/", new(bytes.Buffer))

	cookie := http.Cookie{
		Name:  "mpindemo_session",
		Value: "123"}

	c.App.Store.Put(cookie.Value, session{User: "foo"})

	r.AddCookie(&cookie)

	sessionHandler(c, w, r)

	validateSetCookie(t, c, w, "123", "foo")
}

func TestIndexHandler(t *testing.T) {

	c, w, r := prepare("GET", "/", new(bytes.Buffer))

	indexHandler(c, w, r)

}

func TestIndexHandlerPath(t *testing.T) {

	c, w, r := prepare("GET", "/foo", new(bytes.Buffer))

	indexHandler(c, w, r)

}

func TestIndexHandlerMathod(t *testing.T) {

	c, w, r := prepare("PUT", "/", new(bytes.Buffer))

	indexHandler(c, w, r)

}

func TestPermitUserHandler(t *testing.T) {

	c, w, r := prepare("GET", "/", new(bytes.Buffer))

	s, err := permitUserHandler(c, w, r)

	if s != 200 || err != nil {
		t.Fatal("Handler returned wrong status")
	}

}

func TestPermitUserHandlerMethod(t *testing.T) {

	c, w, r := prepare("POST", "/", new(bytes.Buffer))

	s, _ := permitUserHandler(c, w, r)

	if s != 405 {
		t.Fatal("Handler returned wrong status")
	}

}

func TestProtectedHandler(t *testing.T) {
	c, w, r := prepare("GET", "/protected", new(bytes.Buffer))

	cookie := http.Cookie{
		Name:  "mpindemo_session",
		Value: "123"}

	c.App.Store.Put(cookie.Value, session{User: "foo"})

	r.AddCookie(&cookie)
	c.LoggedUser = "foo"

	protectedHandler(c, w, r)

}

type verifyUserTest struct {
	req        verifyUserRequest
	deviceName string
	method     string
	ok         bool
	status     int 
}

var verifyUserData = []verifyUserTest{
	{
		req: verifyUserRequest{
			MpinID:      "abcdefABCDEF1234567890",
			UserID:      "abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcde!-:",
			ExpireTime:  "1234567890-TZ:123456",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         true,
		status:     200,
	},
	{
		req: verifyUserRequest{
			MpinID:      "abcdefABCDEF1234567890",
			UserID:      "?",
			ExpireTime:  "1234567890-TZ:123456",
			ActivateKey:  "abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCDEF12345678",
			ActivationCode: 1234567889012,
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         true,
		status:     200,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aahkia",
			UserID:      "foo",
			ExpireTime:  "",
			ActivateKey: "dummy",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "GET",
		ok:         false,
		status:     405,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghi",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     403,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:	     0,
		},
		deviceName: "PC",
		method:	    "POST",
		ok:	    false,
		status:     403,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "テストユーザ",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     403,
	},
	{
		req: verifyUserRequest{
			MpinID:      "テスト",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      ":-",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "g",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "G",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "1234567890123456789",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "123456789012345678901",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "TIME;123456789012345",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "A",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCDEF1234567",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCDEF123456789",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "テストテストテストテストテストテストテストa",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: ":-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
			Mobile:      1,
		},
		deviceName: "Mobile",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "dummy",
			ActivationCode: 1234567890123,
			Mobile:      0,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "TestUser",
			ExpireTime:  "12345678901234567890",
			ActivateKey: "dummy",
			ActivationCode: 123456789012,
			Mobile:      2,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         false,
		status:     400,
	},
}

var verifyUserData2 = []verifyUserTest{
	{
		req: verifyUserRequest{
			MpinID:      "abcdefABCDEF1234567890",
			UserID:      "abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcde!-:",
			ExpireTime:  "1234567890-TZ:123456",
			ActivateKey: "dummy",
			Mobile:      0,
			ActivationCode: 2,
		},
		deviceName: "PC",
		method:     "POST",
		ok:         true,
	},
}

func TestVerifyUserHandlerBasic(t *testing.T) {

	for _, d := range verifyUserData {
		testVerifyUserHandlerBasic(t, d.req, d.deviceName, d.method, d.ok,d.status)
	}
	for _, d := range verifyUserData2 {
		testVerifyUserHandlerBasic2(t, d.req, d.deviceName, d.method, d.ok)
	}

}

func testVerifyUserHandlerBasic(t *testing.T, req verifyUserRequest, deviceName, method string, ok bool , status int) {

	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)

	c, w, r := prepare(method, "/", buff)

	var check struct {
		UserID      string
		DeviceName  string
		ValidateURL string
	}

	c.App.Mail = func(userID, deviceName, validateURL string, o *options) (err error) {
		check.DeviceName = deviceName
		check.UserID = userID
		check.ValidateURL = validateURL
		return nil
	}
	c.App.Options.ForceActivate = false
	c.SessionID = "345"

	s, err := verifyUserHandler(c, w, r)

	if s != status{
		t.Fatalf("Status code expected: %v but %v", s , status)
	}
	if err != nil && ok {
		t.Fatalf("Error not expected: %v", err)
	}
	if err != nil && !ok {
		return
	}

	t.Logf("response code %v", w.Code)

	var resp verifyUserResponse

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal("Failed to decode response, ", err, w.Body.String())
	}

	validateURL := fmt.Sprintf("%v?i=%v&e=%v&s=%v",
		c.App.Options.VerifyIdentityURL,
		req.MpinID,
		req.ExpireTime,
		req.ActivateKey)

	if resp.ForceActivate != c.App.Options.ForceActivate ||
		check.DeviceName != deviceName ||
		check.UserID != req.UserID ||
		check.ValidateURL != validateURL {
		t.Fatalf("Wrong data encoded in verify URL, %+v", check)
	}

}

func testVerifyUserHandlerBasic2(t *testing.T, req verifyUserRequest, deviceName, method string, ok bool) {

	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)

	c, w, r := prepare(method, "/", buff)

	c.App.Mail = func(userID, deviceName, validateURL string, o *options) (err error) {
		return errors.New("Failed to send mail")
	}
	c.App.Options.ForceActivate = false
	c.SessionID = "345"
	_, err := verifyUserHandler(c, w, r)
	if err != nil && ok {
		t.Fatalf("Error not expected: %v", err)
	}
	if err != nil && !ok {
		return
	}

	t.Logf("response code %v", w.Code)

	var resp verifyUserResponse

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal("Failed to decode response, ", err, w.Body.String())
	}

	if resp.ForceActivate != c.App.Options.ForceActivate {
		t.Fatalf("Wrong data encoded in verify URL")
	}

}

type verifyUserActivationCodeTest struct {
	req        verifyUserRequest
	activationCodeString string
	deviceName string
	method     string
	ok         bool
}


var verifyUserActivationCodeData = []verifyUserActivationCodeTest{
	{
		req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "root@localhost",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 1,
			Mobile:      0,
		},
		activationCodeString: "0000-0000-0001",
		deviceName: "PC",
		method:     "POST",
		ok:         true,
	},
	{
	req: verifyUserRequest{
			MpinID:      "aaa",
			UserID:      "root@localhost",
			ExpireTime:  "12345678901234567890",
			ActivationCode: 999999999999,
			Mobile:      0,
		},
		activationCodeString: "9999-9999-9999",
		deviceName: "PC",
		method:     "POST",
		ok:         true,
	},
}

func TestVerifyUserHandlerBasicActivationCode(t *testing.T) {

	for _, d := range verifyUserActivationCodeData{
		testVerifyUserHandlerBasicActivationCode(t, d.req, d.activationCodeString,d.deviceName, d.method, d.ok)
	}

}

func testVerifyUserHandlerBasicActivationCode(t *testing.T, req verifyUserRequest, activationCodeString, deviceName, method string, ok bool) {

	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)

	c, w, r := prepare(method, "/", buff)

	user, err := user.Current()
	mailAddress :=  user.Username + "@localhost.localdomain"
	if err != nil{
		t.Error(err)
	}
	originAppOptionsForceActivate := c.App.Options.ForceActivate
	originAppOptionsEmailSender := c.App.Options.EmailSender
	originAppOptionsEmailSubject := c.App.Options.EmailSubject

	c.App.Options.ForceActivate = false
	c.App.Options.EmailSender = mailAddress
	c.App.Options.EmailSubject = "emailSubject"

	_, err = verifyUserHandler(c, w, r)
	if err != nil && ok {
		t.Fatalf("Error not expected: %v", err)
	}
	if err != nil && !ok {
		return
	}

	t.Logf("response code %v", w.Code)

	var resp verifyUserResponse

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal("Failed to decode response, ", err, w.Body.String())
	}

	if resp.ForceActivate != c.App.Options.ForceActivate{
		t.Fatalf("Fact Value(resp.ForceActivate)%v, Expected Value(c.App.options.ForceActivate) %v", resp.ForceActivate, c.App.Options.ForceActivate)
	}
	
	mailSubject := "emailSubject"
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

	c.App.Options.ForceActivate = originAppOptionsForceActivate
	c.App.Options.EmailSender = originAppOptionsEmailSender
	c.App.Options.EmailSubject = originAppOptionsEmailSubject

	header := fmt.Sprintf("From: %v\nTo: %v\nSubject: %v\n", mailAddress, mailAddress, mailSubject)
	if strings.Index(content[lastIndex:], header) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], header)
	}

	if strings.Index(content[lastIndex:], activationCodeString) == -1 {
		t.Errorf("mail = <%s> want including <%s>", content[lastIndex:], activationCodeString)
	}
}

type verifyUserSanitizingTest struct {
	req	string
	ok         bool
	status     int
}

var verifyUserSanitizingData = []verifyUserSanitizingTest{
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":0,"activationCode":0,"resend":"on","deviceName":"Name","userData":"Data"}`,
		ok: true,
		status: 200,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":1,"activateKey":"abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCDEF12345678","resend":"on","deviceName":"Name","userData":"Data"}`,
		ok: true,
		status: 200,
	},
	{
		req:  `{nil: nil,"userId": "TestUser","expireTime": "12345678901234567890","mobile":1}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId": "aaa","userId": "root@localhost","expireTime": "12345678901234567890","mobile": 1,"activateKey": "dummy","activationCode": 0,"Dummy": "dummy"}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"userId":"TestUser","expireTime":"12345678901234567890","mobile":0,"activateKey":"dummy","activationCode":0}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","expireTime":"12345678901234567890","mobile":0,"activateKey":"dummy","activationCode":0}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","mobile":0,"activateKey":"abc123","activationCode":0}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","activateKey":"abc123","activationCode":0}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":1,"activationCode":0}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":0,"activateKey":"abc123"}`,
		ok: false,
		status: 400,
	},
	{
		req:  `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":0,"activationCode":"JSONERROR"}`,
		ok: false,
		status: 500,
	},
}

func TestVerifyUserHandlerBasicSanitizing(t *testing.T) {

	for _, d := range verifyUserSanitizingData{
		buff := bytes.NewBufferString(d.req)
		c, w, r := prepare("POST", "/", buff)
		testverifyUserHandlerBasicSanitizing(t, c, w, r, d.ok, d.status)
	}
}

func testverifyUserHandlerBasicSanitizing(t *testing.T, c *context, w http.ResponseWriter, r *http.Request, ok bool , status int) {
	c.SessionID = "345"
	s, err := verifyUserHandler(c, w, r)

	if s != status{
		t.Fatalf("Status code expected: %v but %v", s , status)
	}
	if err != nil && ok {
		t.Fatalf("Error not expected: %v", err)
	}
	if err != nil && !ok {
		return
	}
	t.Logf("response code %v", s)
}

func TestVerifyUserForceActivateTrue(t *testing.T) {
	req := `{"mpinId":"aaa","userId":"TestUser","expireTime":"12345678901234567890","mobile":0,"activationCode":0,"resend":"on","deviceName":"Name","userData":"Data"}`
	buff := bytes.NewBufferString(req)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"
	originAppOptionsForceActivate := c.App.Options.ForceActivate
	c.App.Options.ForceActivate = true
	s, err := verifyUserHandler(c, w, r)
	c.App.Options.ForceActivate = originAppOptionsForceActivate
	status := 200
	if s != status{
		t.Fatalf("Status code expected: %v but %v", s , status)
	}
	if err != nil {
		t.Fatalf("Error not expected: %v", err)
	}

	t.Logf("response code %v", s)
}

func TestVerifyUserHandlerLDAPOK(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "root@localhost",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	
	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		_, err := verifyUserHandler(c, w, r)
		if err != nil {
			t.Errorf("Error not expected: %v", err)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort

}

func TestVerifyUserHandlerLDAPBindOK(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "root@localhost",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	
	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort
	originAppOptionsLDAPBindDN := c.App.Options.LDAPBindDN
	originAppOptionsLDAPBindPWD := c.App.Options.LDAPBindPWD

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389
	c.App.Options.LDAPBindDN = "cn=testy,o=testers,c=test"
	c.App.Options.LDAPBindPWD = "iLike2test"

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		_, err := verifyUserHandler(c, w, r)
		if err != nil {
			t.Errorf("Error not expected: %v", err)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort
	c.App.Options.LDAPBindDN = originAppOptionsLDAPBindDN
	c.App.Options.LDAPBindPWD = originAppOptionsLDAPBindPWD

}

func TestVerifyUserHandlerLDAPConnectNG(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "root@localhost",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.0"
	c.App.Options.LDAPPort = 10389

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 500
		s, err := verifyUserHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort

}

func TestVerifyUserHandlerLDAPTLSConnectNG(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "root@localhost",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	oBuckup := o
	o = options{CACertFile: "./test/cacert/cacert.pem"}

	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"
	o = oBuckup

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort
	originAppOptionsLDAPUseTLS := c.App.Options.LDAPUseTLS

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.0"
	c.App.Options.LDAPPort = 14389
	c.App.Options.LDAPUseTLS = true

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 500
		s, err := verifyUserHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort
	c.App.Options.LDAPUseTLS = originAppOptionsLDAPUseTLS
	
}

func TestVerifyUserHandlerLDAPBindNG(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "root@localhost",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort
	originAppOptionsLDAPBindDN := c.App.Options.LDAPBindDN
	originAppOptionsLDAPBindPWD := c.App.Options.LDAPBindPWD

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389
	c.App.Options.LDAPBindDN = "cn=testy,o=testers,c=test"
	c.App.Options.LDAPBindPWD = "invalid"

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 500
		s, err := verifyUserHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort
	c.App.Options.LDAPBindDN = originAppOptionsLDAPBindDN
	c.App.Options.LDAPBindPWD = originAppOptionsLDAPBindPWD

}

func TestVerifyUserHandlerLDAPSearchNG(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "invalid",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchPanic{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 500
		s, err := verifyUserHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort

}

func TestVerifyUserHandlerLDAPSearchNotFoundOK(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "invalid",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidEmpty{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 200
		s, err := verifyUserHandler(c, w, r)
		if err != nil {
			t.Errorf("Error not expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort

}

func TestVerifyUserHandlerLDAPSearchNotFoundNG(t *testing.T) {

	req := verifyUserRequest{
		MpinID:      "aaa",
		UserID:      "invalid",
		ExpireTime:  "12345678901234567890",
		ActivateKey: "dummy",
		Mobile:      0,
	}
	body, _ := json.Marshal(req)
	buff := bytes.NewBuffer(body)
	c, w, r := prepare("POST", "/", buff)
	c.SessionID = "345"

	originAppOptionsLDAPVerify := c.App.Options.LDAPVerify
	originAppOptionsLDAPVerifyShow := c.App.Options.LDAPVerifyShow
	originAppOptionsLDAPServer := c.App.Options.LDAPServer
	originAppOptionsLDAPPort := c.App.Options.LDAPPort

	c.App.Options.LDAPVerify = true
	c.App.Options.LDAPVerifyShow = true
	c.App.Options.LDAPServer = "127.0.0.1"
	c.App.Options.LDAPPort = 10389

	time.Sleep(wait)
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := ldap.NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimpleUidEmpty{})
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		status := 403
		s, err := verifyUserHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		if s != status {
			t.Errorf("Status code expected: %v but %v", status, s)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true

	c.App.Options.LDAPVerify = originAppOptionsLDAPVerify
	c.App.Options.LDAPVerifyShow = originAppOptionsLDAPVerifyShow
	c.App.Options.LDAPServer = originAppOptionsLDAPServer
	c.App.Options.LDAPPort = originAppOptionsLDAPPort

}

type testAuthUser struct {
	body   string
	OTP    bool
	method string
	status int
	// expected
	authOTT string
	userID  string
	message string
	code    int
	ok      bool
}

var testAuthUserData = []testAuthUser{
	{
		body:    `{"mpinResponse": {"authOTT": "1234567890abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCD","version":"info","pass":"key"}}`,
		OTP:     true,
		method:  "POST",
		status:  200,
		authOTT: "1234567890abcdefABCDEF1234567890abcdefABCDEF1234567890abcdefABCD",
		userID:  "foo",
		message: "It's a test",
		code:    200,
		ok:      true,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "1234567890123456789012345678901234567890123456789012345678901234"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "1234567890123456789012345678901234567890123456789012345678901234",
		userID:  "foo",
		message: "It's a test",
		code:    200,
		ok:      true,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "123"}}`,
		OTP:     false,
		method:  "GET",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    405,
		ok:      false,
	},
	{
		body:    `{mpinRespoAAAnse": {"authOTT": "123"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"Dummy":"dummy","mpinResponse": {"authOTT": "123"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    "{}",
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "123","Dummy":"dummy"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"version":"info","pass":"key"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": 123}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "123456789012345678901234567890123456789012345678901234567890123"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "123456789012345678901234567890123456789012345678901234567890123",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "12345678901234567890123456789012345678901234567890123456789012345"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "12345678901234567890123456789012345678901234567890123456789012345",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "テストテストテストテストテストテストテストa"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: "テストテストテストテストテストテストテストa",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": ":-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_"}}`,
		OTP:     false,
		method:  "POST",
		status:  200,
		authOTT: ":-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_:-!?{}&/.,@[]|^_",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"}}`,
		method:  "POST",
		status:  200,
		authOTT: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
	{
		body:    `{"mpinResponse": {"authOTT": "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"}}`,
		method:  "POST",
		status:  200,
		authOTT: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
		userID:  "foo",
		message: "It's a test",
		code:    400,
		ok:      false,
	},
}

func testAuthenticateUser(t *testing.T, d testAuthUser) {

	t.Logf("Test case: %+v", d)

	buff := bytes.NewBufferString(d.body)

	c, w, r := prepare(d.method, "/", buff)

	var checkAuth struct {
		authOTT string
	}

	c.App.Authenticate = func(c *context, authOTT string) (userID, message string, status int) {
		checkAuth.authOTT = authOTT
		return d.userID, d.message, d.status
	}

	var checkLoginResult struct {
		userID  string
		authOTT string
		status  int
		message string
	}

	c.App.LoginResult = func(c *context, userID, authOTT string, status int, message string) error {
		checkLoginResult.userID = userID
		checkLoginResult.authOTT = authOTT
		checkLoginResult.status = status
		checkLoginResult.message = message
		return nil
	}

	c.App.Options.RequestOTP = d.OTP
	c.SessionID = "345"

	status, err := authenticateUserHandler(c, w, r)

	t.Logf("Auth check %+v", checkAuth)
	t.Logf("Login check %+v", checkLoginResult)

	if !d.ok && err != nil && status == d.code {
		// expected error
		return
	}

	if status != d.code ||
		(err == nil && !d.ok || err != nil && !d.ok) ||
		checkAuth.authOTT != d.authOTT ||
		checkLoginResult.userID != d.userID ||
		checkLoginResult.authOTT != d.authOTT ||
		checkLoginResult.status != d.status ||
		checkLoginResult.message != d.message {
		t.Fatal("Response, ", status, err, w.Body.String())
	}

	if d.OTP {
		var resp authOTPResponse

		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal("Failed to decode response, ", err, w.Body.String())
		}
		if resp.TTLSeconds != 64 ||
			math.Abs(float64(resp.NowTime-time.Now().Unix()*1000)) > 2000 ||
			math.Abs(float64(resp.ExpireTime-resp.NowTime-resp.TTLSeconds*1000)) > 2000 {
			t.Fatal("Bad times in response")
		}
	} else {
		var resp authRPAResponse

		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal("Failed to decode response, ", err, w.Body.String())
		}
		if len(resp.SomeUserData) == 0 {
			t.Fatal("Empty user data")
		}
	}

}

func TestAuthenticateUser(t *testing.T) {
	for _, d := range testAuthUserData {
		testAuthenticateUser(t, d)
	}
}

type testLogoutHandler struct {
	body string
}

var testLogoutHandlerData = []testLogoutHandler{
	{
		body: `{"sessionToken": "123", "userId":"user01"}`,
	},
	{
		body: `{"sessionToken"}`,
	},
}

func TestLogoutHandler(t *testing.T) {
	for _, d := range testLogoutHandlerData {
		c, w, r := prepare("POST", "/protected", bytes.NewBufferString(d.body))
		c.SessionID = "123"

		s, err := logoutHandler(c, w, r)
		if err == nil {
			t.Errorf("Error expected: %v", err)
		}
		status := 400
		if s != status {
			t.Fatalf("Status code expected: %v but %v", s , status)
		}
	}
}

/////////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (uint8, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

type searchSimple struct {
}

func (s searchSimple) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	entries := []*ldap.Entry{
		&ldap.Entry{"cn=ned,o=testers,c=test", []*ldap.EntryAttribute{
			&ldap.EntryAttribute{"cn", []string{"ned"}, nil},
			&ldap.EntryAttribute{"o", []string{"ate"}, nil},
			&ldap.EntryAttribute{"uidNumber", []string{"5000"}, nil},
			&ldap.EntryAttribute{"accountstatus", []string{"active"}, nil},
			&ldap.EntryAttribute{"uid", []string{"root@localhost"}, nil},
			&ldap.EntryAttribute{"description", []string{"ned via sa"}, nil},
			&ldap.EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
		&ldap.Entry{"cn=trent,o=testers,c=test", []*ldap.EntryAttribute{
			&ldap.EntryAttribute{"cn", []string{"trent"}, nil},
			&ldap.EntryAttribute{"o", []string{"ate"}, nil},
			&ldap.EntryAttribute{"uidNumber", []string{"5005"}, nil},
			&ldap.EntryAttribute{"accountstatus", []string{"active"}, nil},
			&ldap.EntryAttribute{"uid", []string{"trent"}, nil},
			&ldap.EntryAttribute{"description", []string{"trent via sa"}, nil},
			&ldap.EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
		&ldap.Entry{"cn=randy,o=testers,c=test", []*ldap.EntryAttribute{
			&ldap.EntryAttribute{"cn", []string{"randy"}, nil},
			&ldap.EntryAttribute{"o", []string{"ate"}, nil},
			&ldap.EntryAttribute{"uidNumber", []string{"5555"}, nil},
			&ldap.EntryAttribute{"accountstatus", []string{"active"}, nil},
			&ldap.EntryAttribute{"uid", []string{"randy"}, nil},
			&ldap.EntryAttribute{"objectclass", []string{"posixaccount"}, nil},
		}},
	}
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchSimpleUidEmpty struct {
}

func (s searchSimpleUidEmpty) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	return ldap.ServerSearchResult{[]*ldap.Entry{}, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}

type searchPanic struct {
}

func (s searchPanic) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	entries := []*ldap.Entry{}
	panic("this is a test panic")
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}
