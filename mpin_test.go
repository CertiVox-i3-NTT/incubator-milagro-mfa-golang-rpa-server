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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// type identity struct {
//     UserID string `json:"userID"`
//     Issued string `json:"issued"`
//     Mobile int    `json:"mobile"`
//  }

func encodeIdentity(identity string, expires string, activateKey string) string {

	data := url.Values{}
	data.Set("i", identity)
	data.Set("e", expires)
	data.Set("s", activateKey)

	return data.Encode()
}

func testVerifySignature(t *testing.T, i string, expires, activateKey string, expected signature, valid bool, session string) {

	t.Logf("Test data: i: %v, expires: %v, activateKey: %v, expected: %+v", i, expires, activateKey, expected)

	c := context{App: testApp()}
	c.SessionID = session

	body := encodeIdentity(i, expires, activateKey)
	t.Logf("Encoded identity %v", body)

	//r, err := http.NewRequest("POST", "/", bytes.NewBufferString(body))
	//r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := http.NewRequest("POST", fmt.Sprintf("/?%v", body), new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	s, err := verifySignature(&c, r)

	if s.IsValid && s != expected || valid && err != nil || !valid && err == nil {
		t.Logf("Expected: %v -- %+v", valid, expected)
		t.Fatalf("Found: %v -- %+v", err, s)
	}
}

type signatureTest struct {
	i           string
	expires     string
	activateKey string
	expected    signature
	valid       bool
	Session     string
}

var testSignatureData = []signatureTest{
	// valid case
	signatureTest{
		i:           hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 0}`)),
		expires:     "2100-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected: signature{
			Identity:    hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 0}`)),
			UserID:      "foo",
			Issued:      "2000-01-01 00:00:00",
			HumanIssued: "01 Jan 00 00:00 +0000",
			DeviceName:  "PC",
			ActivateKey: "dsfdsfasfdsf",
			IsValid:     true,
		},
		valid: true,
		Session: "345",
	},
	// valid case mobile
	signatureTest{
		i:           hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 1}`)),
		expires:     "2100-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected: signature{
			Identity:    hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 1}`)),
			UserID:      "foo",
			Issued:      "2000-01-01 00:00:00",
			HumanIssued: "01 Jan 00 00:00 +0000",
			DeviceName:  "Mobile",
			ActivateKey: "dsfdsfasfdsf",
			IsValid:     true,
		},
		valid: true,
		Session: "345",
	},
	// invalid json
	signatureTest{
		i:           hex.EncodeToString([]byte(`{userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 0}`)),
		expires:     "2100-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected:    signature{},
		valid:       false,
		Session: "345",
	},
	// invalid time
	signatureTest{
		i:           hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-0101 00:00:00", "mobile": 0}`)),
		expires:     "2100-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected:    signature{},
		valid:       false,
		Session: "345",
	},
	// no user id
	signatureTest{
		i:           hex.EncodeToString([]byte(`{"userID": "", "issued": "2000-01-01 00:00:00", "mobile": 0}`)),
		expires:     "2100-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected:    signature{},
		valid:       false,
		Session: "345",
	},
	// expired
	signatureTest{
		i:           hex.EncodeToString([]byte(`{"userID": "foo", "issued": "2000-01-01 00:00:00", "mobile": 0}`)),
		expires:     "2000-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected:    signature{},
		valid:       false,
		Session: "345",
	},
	// wrong hex
	signatureTest{
		i:           "2167421211j19",
		expires:     "2000-01-01T00:00:00Z",
		activateKey: "dsfdsfasfdsf",
		expected:    signature{},
		valid:       false,
		Session: "345",
	},
}

func TestSignature(t *testing.T) {

	for _, d := range testSignatureData {

		testVerifySignature(t, d.i, d.expires, d.activateKey, d.expected, d.valid, d.Session)
	}

}

func TestVerifySignatureParseFormError(t *testing.T) {

	c := context{App: testApp()}
	c.SessionID = "345"

	body := "%ParseFormError"

	r, err := http.NewRequest("POST", fmt.Sprintf("/?%v", body), new(bytes.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	s, err := verifySignature(&c, r)

	if err == nil {
		t.Logf("Expected: %v -- %+v", false, signature{})
		t.Fatalf("Found: %v -- %+v", err, s)
	}
}

// Authenticate to RPS

type testRPSAuth struct {
	AuthOTT string
	User    string
	Message string
	Status  int
	Session string
	E       error
}

func testAuthenticateToRPS(t *testing.T, authOTT, user, message, session string, status int, e error) {

	t.Logf("Case %v - %v - %v - %v - %v - %v", authOTT, user, message, session, status, e)

	c := context{App: testApp()}
	c.SessionID = session
	c.App.Fetch = func(a *app, url string, method string, q interface{}, d interface{}) (err error) {

		rq, ok := q.(*authRPSRequest)
		if !ok {
			t.Fatalf("Wrong request struct %+v", q)
		}

		if rq.AuthOTT != authOTT || rq.LogoutData.SessionToken != session {
			t.Fatalf("RPS request data wrong, %+v", rq)
		}
		response := fmt.Sprintf(`{"userId": "%v", "status": %v, "message": "%v"}`, user, status, message)
		json.Unmarshal([]byte(response), d)
		return e
	}

	u, m, s := authenticateToRPS(&c, authOTT)

	if u != user || m != message || s != status {
		t.Fatalf("Different data returned")
	}

}

var testRPSAuthData = []testRPSAuth{
	testRPSAuth{
		AuthOTT: "123",
		User:    "foo",
		Message: "bar",
		Status:  200,
		Session: "345",
		E:       nil,
	},
	testRPSAuth{
		AuthOTT: "123",
		User:    "",
		Message: "Server error",
		Status:  0,
		Session: "345",
		E:       errors.New("test error"),
	},
}

func TestAuthenticateToRPS(t *testing.T) {

	for _, d := range testRPSAuthData {
		testAuthenticateToRPS(t, d.AuthOTT, d.User, d.Message, d.Session, d.Status, d.E)
	}

}

func testSendLoginResult(t *testing.T, userID, authOTT, message, session string, status int) {

	t.Logf("Case %v - %v - %v - %v - %v", authOTT, userID, message, session, status)

	c := context{App: testApp()}
	c.SessionID = session
	c.App.Fetch = func(a *app, url string, method string, q interface{}, d interface{}) (err error) {

		rq, ok := q.(*sendLoginResultReq)
		if !ok {
			t.Fatalf("Wrong request struct %+v", q)
		}
		if rq.AuthOTT != authOTT ||
			rq.LogoutData.SessionToken != session ||
			rq.Message != message ||
			rq.Status != status ||
			rq.LogoutData.UserID != userID {
			t.Fatalf("RPS request data wrong, %+v", rq)
		}
		return nil
	}

	if err := sendLoginResult(&c, userID, authOTT, status, message); err != nil {
		t.Fatal(err)
	}

	if item, err := c.App.Store.Get(c.SessionID); status == 200 && (err != nil || item.User != userID) {
		t.Fatal(err)
	}
}

type testSendLogin struct {
	AuthOTT string
	User    string
	Message string
	Status  int
	Session string
}

var testSendLoginData = []testSendLogin{
	testSendLogin{
		AuthOTT: "123",
		User:    "foo",
		Message: "bar",
		Status:  200,
		Session: "345",
	},
	testSendLogin{
		AuthOTT: "123",
		User:    "foo",
		Message: "Server error",
		Status:  0,
		Session: "345",
	},
}

func TestSendLoginResult(t *testing.T) {

	for _, d := range testSendLoginData {
		testSendLoginResult(t, d.User, d.AuthOTT, d.Message, d.Session, d.Status)
	}

}

func testActivateUser(t *testing.T, activateKey, identity string, e error) {

	t.Logf("Case %v - %v - %v", activateKey, identity, e)

	c := context{App: testApp()}
	c.SessionID = "345"
	expURL := fmt.Sprintf("%v://%v/user/%v", c.App.Options.RPSSchema, c.App.Options.RPSHost, identity)

	c.App.Fetch = func(a *app, url string, method string, q interface{}, d interface{}) (err error) {

		rq, ok := q.(*struct {
			ActivateKey string `json:"activateKey"`
		})
		if !ok {
			t.Fatalf("Wrong request struct %+v", q)
		}
		if rq.ActivateKey != activateKey ||
			url != expURL ||
			method != "POST" {
			t.Fatalf("RPS request data wrong, %+v", rq)
		}
		return e
	}

	if err := activateUserRPS(&c, identity, activateKey); err != e {
		t.Fatal(err)
	}
}

type activateUserTest struct {
	ActivateKey string
	Identity    string
	E           error
}

var activateUserTestData = []activateUserTest{
	{
		ActivateKey: "123",
		Identity:    "345",
		E:           nil,
	},
	{
		ActivateKey: "123",
		Identity:    "345",
		E:           errors.New("Test"),
	},
}

func TestActivateUser(t *testing.T) {

	for _, d := range activateUserTestData {
		testActivateUser(t, d.ActivateKey, d.Identity, d.E)
	}

}
