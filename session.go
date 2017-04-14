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
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
)

func createNewSession(c *context, w http.ResponseWriter) {
	c.SessionID = generateSessionID()
	c.LoggedUser = ""
	log.Printf("D Generated new SessionID: {%v}", c.SessionID)
	c.App.Store.Put(c.SessionID, session{User: ""})
	setSecureCookie(w, &http.Cookie{Name: "mpindemo_session", Value: c.SessionID, MaxAge: 60 * 60 * 4}, c.App.Options.UseSecureCookie)
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error: ", err)
		return ""
	}
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
