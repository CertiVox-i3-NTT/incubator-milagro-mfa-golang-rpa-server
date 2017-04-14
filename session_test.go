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
	"regexp"
	"testing"
	"net/http"
	"net/http/httptest"
)

func TestCreateNewSession(t *testing.T) {
	o := options{UseSecureCookie: false}
	a := app{Store: make(storage), Options: &o}
	c := context{App: &a}
	reg := regexp.MustCompile("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")

	handler := func(w http.ResponseWriter, r *http.Request) {
		createNewSession(&c, w)
		if !reg.MatchString(c.SessionID) {
			t.Errorf("c.SessionID <%s> want XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", c.SessionID)
		}
		if c.LoggedUser != "" {
			t.Errorf("c.LoggedUser <%s> want <%s>", c.LoggedUser, "")
		}
		item, err := c.App.Store.Get(c.SessionID)
		if err != nil {
			t.Error(err)
		}
		if item.User != "" {
			t.Errorf("storage[session].User = <%s> want <%s>", item.User, "")
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	res, err := http.Get(server.URL)
	if err != nil {
		t.Error(err)
	}
	cookies := res.Cookies()
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == "mpindemo_session" && cookies[i].Value != c.SessionID {
			t.Errorf("cookie.Value = <%s> want <%s>", cookies[i].Value, c.SessionID)
		}
		if cookies[i].Name == "mpindemo_session" && cookies[i].MaxAge != 60 * 60 * 4 {
			t.Errorf("cookie.MaxAge = <%d> want <%d>", cookies[i].MaxAge, 60 * 60 * 4)
		}
		if cookies[i].Name == "mpindemo_session" && cookies[i].Secure != false {
			t.Errorf("cookie.Secure = <%t> want <%t>", cookies[i].Secure, false)
		}
	}

}

func TestGenerateSessionID(t *testing.T) {
	reg := regexp.MustCompile("^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")

	sessionId := generateSessionID()
	if !reg.MatchString(sessionId) {
		t.Errorf("generate session ID <%s> want XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", sessionId)
	}
}
