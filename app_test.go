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
	"time"
)

func TestPutNotSetExpires(t *testing.T) {
	store := make(storage)
	sessionId := "sessionId"
	user := "user"

	expiresStart := time.Now().Add(time.Duration(4 * time.Hour))
	err := store.Put(sessionId, session{User: user})
	expiresEnd := time.Now().Add(time.Duration(4 * time.Hour))
	if err != nil {
		t.Error(err)
	}
	if expiresStart.After(store[sessionId].Expires) && expiresEnd.Before(store[sessionId].Expires) {
		t.Errorf("Expires = <%s> want between from <%s> to <%s>", store[sessionId].Expires, expiresStart, expiresEnd)
	}
	if store[sessionId].User != user {
		t.Errorf("User = <%s> want <%s>", store[sessionId].User, user)
	}
}

func TestPutSetExpires(t *testing.T) {
	store := make(storage)
	sessionId := "sessionId"
	expires := time.Unix(0, 0)
	user := "user"

	err := store.Put(sessionId, session{Expires: expires, User: user})
	if err != nil {
		t.Error(err)
	}
	if store[sessionId].Expires != expires {
		t.Errorf("Expires = <%s> want <%s>", store[sessionId].Expires, expires)
	}
	if store[sessionId].User != user {
		t.Errorf("User = <%s> want <%s>", store[sessionId].User, user)
	}
}

func TestGetFound(t *testing.T) {
	store := make(storage)
	sessionId := "sessionId"
	user := "user"

	store.Put(sessionId, session{User: user})
	expiresStart := time.Now().Add(time.Duration(4 * time.Hour))
	item, err := store.Get(sessionId)
	expiresEnd := time.Now().Add(time.Duration(4 * time.Hour))
	if err != nil {
		t.Error(err)
	}
	if expiresStart.After(item.Expires) && expiresEnd.Before(item.Expires) {
		t.Errorf("Expires = <%s> want between from <%s> to <%s>", item.Expires, expiresStart, expiresEnd)
	}
	if item.User != user {
		t.Errorf("User = <%s> want <%s>", item.User, user)
	}
}

func TestGetNotFoound(t *testing.T) {
	store := make(storage)
	sessionId := "sessionId"
	errMssage := "SessionID not found"

	_, err := store.Get(sessionId)
	if err == nil || err.Error() != errMssage {
		t.Errorf("err = <%s> want <%s>", err, errMssage)
	}
}

func TestGetExpires(t *testing.T) {
	store := make(storage)
	sessionId := "sessionId"
	user := "user"
	errMssage := "SessionID expired"

	store.Put(sessionId, session{Expires: time.Unix(0, 0), User: user})
	_, err := store.Get(sessionId)
	if err == nil || err.Error() != errMssage {
		t.Errorf("err = <%s> want <%s>", err, errMssage)
	}
}

func TestNewApp(t *testing.T) {
	a := newApp()

	if a == nil {
		t.Error("newApp() failed")
	}
}

func TestNewAppCACert(t *testing.T) {
	oBuckup := o
	o = options{CACertFile: "./test/cacert/cacert.pem"}

	a := newApp()

	if a == nil {
		t.Error("newApp() failed")
	}
	o = oBuckup
}
