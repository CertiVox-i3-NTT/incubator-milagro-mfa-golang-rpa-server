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
	"errors"
	"net/http"
	"time"
)

func getSecureCookie(r *http.Request, name string, secure bool) (cookie *http.Cookie, err error) {
	if cookie, err = r.Cookie(name); err != nil {
		return cookie, err
	}
	if cookie == nil {
		// strange, but that happens
		return cookie, errors.New("Nil cookie without error")
	}
	if !secure {
		return cookie, err
	}
	return cookie, err
}

func setSecureCookie(w http.ResponseWriter, cookie *http.Cookie, secure bool) {
	if !secure {
		cookie.Secure = false
		cookie.HttpOnly = false
	} else {
		cookie.Secure = true
		cookie.HttpOnly = true
	}
	http.SetCookie(w, cookie)
}

func deleteCookie(w http.ResponseWriter, name string) {
	var c http.Cookie
	c.Name = name
	// Expires must be > 0 (time.Unix(0, 0) is invalid as 'Expires'
	c.Expires = time.Unix(1, 0)
	http.SetCookie(w, &c)
}
