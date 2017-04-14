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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetSecureCookieExist(t *testing.T) {
	cookieName := "cookieName"
	cookieValue := "cookieValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		getCookie, errCookie := getSecureCookie(r, cookieName, false)
		if errCookie != nil {
			t.Error(errCookie)
		}
		if (*getCookie).Name != cookieName {
			t.Errorf("cookie.Name = <%s> want <%s>", (*getCookie).Name, cookieName)
		}
		if (*getCookie).Value != cookieValue {
			t.Errorf("cookie.Value = <%s> want <%s>", (*getCookie).Value, cookieValue)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, errReq := http.NewRequest("GET", server.URL, nil)
	if errReq != nil {
		t.Error(errReq)
	}
	cookie := http.Cookie{Name: cookieName, Value: cookieValue}
	req.AddCookie(&cookie)
	_, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		t.Error(errDo)
	}
}

func TestGetSecureCookieExistSecure(t *testing.T) {
	cookieName := "cookieName"
	cookieValue := "cookieValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		getCookie, errCookie := getSecureCookie(r, cookieName, true)
		if errCookie != nil {
			t.Error("on HTTP protocol cookie header don't include secure attribute")
			t.Error(errCookie)
		}
		if (*getCookie).Name != cookieName {
			t.Errorf("cookie.Name = <%s> want <%s>", (*getCookie).Name, cookieName)
		}
		if (*getCookie).Value != cookieValue {
			t.Errorf("cookie.Value = <%s> want <%s>", (*getCookie).Value, cookieValue)
		}
	}

	server := httptest.NewTLSServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, errReq := http.NewRequest("GET", server.URL + "/", nil)
	if errReq != nil {
		t.Error(errReq)
	}
	cookie := http.Cookie{Name: cookieName, Value: cookieValue}
	req.AddCookie(&cookie)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	_, errDo := client.Do(req)
	if errDo != nil {
		t.Error(errDo)
	}
}

func TestGetSecureCookieNotExist(t *testing.T) {
	cookieName := "cookieName"

	handler := func(w http.ResponseWriter, r *http.Request) {
		getCookie, errCookie := getSecureCookie(r, cookieName, false)
		if errCookie == nil {
			t.Error("getSecureCookie = <%s> want error", *getCookie)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, errReq := http.NewRequest("GET", server.URL, nil)
	if errReq != nil {
		t.Error(errReq)
	}
	_, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		t.Error(errDo)
	}
}

func TestSetSecureCookieFalse(t *testing.T) {
	cookieName := "cookieName"
	cookieValue := "cookieValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{Name: cookieName, Value: cookieValue}

		setSecureCookie(w, &cookie, false)
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
		if cookies[i].Name == cookieName && cookies[i].Secure != false {
			t.Errorf("cookie.Secure = <%t> want <%t>", cookies[i].Secure, false)
		}
		if cookies[i].Name == cookieName && cookies[i].HttpOnly != false {
			t.Errorf("cookie.HttpOnly = <%t> want <%t>", cookies[i].HttpOnly, false)
		}
	} 
}

func TestSetSecureCookieTrue(t *testing.T) {
	cookieName := "cookieName"
	cookieValue := "cookieValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{Name: cookieName, Value: cookieValue}

		setSecureCookie(w, &cookie, true)
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
		if cookies[i].Name == cookieName && cookies[i].Secure != true {
			t.Errorf("cookie.Secure = <%t> want <%t>", cookies[i].Secure, true)
		}
		if cookies[i].Name == cookieName && cookies[i].HttpOnly != true {
			t.Errorf("cookie.HttpOnly = <%t> want <%t>", cookies[i].HttpOnly, true)
		}
	} 
}

func TestDeleteCookie0Cookies(t *testing.T) {
	cookieName := "cookieName"

	handler := func(w http.ResponseWriter, r *http.Request) {
		deleteCookie(w, cookieName)
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
	expires := new(time.Time)
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == cookieName && cookies[i].Expires == time.Unix(1, 0).UTC() {
			return
		} else if cookies[i].Name == cookieName {
			*expires = cookies[i].Expires
		}
	}
	t.Errorf("cookie.Expires = <%s> want <%s>", expires, time.Unix(1, 0).UTC())
}

func TestDeleteCookie1Cookies(t *testing.T) {
	cookieName := "cookieName"
	cookieValue := "cookieValue"
	now := time.Now()

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{Name: cookieName, Value: cookieValue, Expires: now}

		http.SetCookie(w, &cookie)
		deleteCookie(w, cookieName)
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
	expires := new(time.Time)
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == cookieName && cookies[i].Expires == time.Unix(1, 0).UTC() {
			return
		} else if cookies[i].Name == cookieName {
			*expires = cookies[i].Expires
		}
	}
	t.Errorf("cookie.Expires = <%s> want <%s>", expires, time.Unix(1, 0).UTC())
}

func TestDeleteCookie2CookiesDeleteFirst(t *testing.T) {
	cookieName := "cookieName"
	cookieName2 := "cookieName2"
	cookieValue := "cookieValue"
	cookieValue2 := "cookieValue2"
	now := time.Now()

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{Name: cookieName, Value: cookieValue, Expires: now}
		cookie2 := http.Cookie{Name: cookieName2, Value: cookieValue2, Expires: now}

		http.SetCookie(w, &cookie)
		http.SetCookie(w, &cookie2)
		deleteCookie(w, cookieName)
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
	expires := new(time.Time)
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == cookieName && cookies[i].Expires == time.Unix(1, 0).UTC() {
			return
		} else if cookies[i].Name == cookieName {
			*expires = cookies[i].Expires
		}
	}
	t.Errorf("cookie.Expires = <%s> want <%s>", expires, time.Unix(1, 0).UTC())
}

func TestDeleteCookie2CookiesDeleteSecond(t *testing.T) {
	cookieName := "cookieName"
	cookieName2 := "cookieName2"
	cookieValue := "cookieValue"
	cookieValue2 := "cookieValue2"
	now := time.Now()

	handler := func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{Name: cookieName, Value: cookieValue, Expires: now}
		cookie2 := http.Cookie{Name: cookieName2, Value: cookieValue2, Expires: now}

		http.SetCookie(w, &cookie)
		http.SetCookie(w, &cookie2)
		deleteCookie(w, cookieName2)
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
	expires := new(time.Time)
	for i := 0; i < len(cookies); i++ {
		if cookies[i].Name == cookieName2 && cookies[i].Expires == time.Unix(1, 0).UTC() {
			return
		} else if cookies[i].Name == cookieName2 {
			*expires = cookies[i].Expires
		}
	}
	t.Errorf("cookie.Expires = <%s> want <%s>", expires, time.Unix(1, 0).UTC())
}
