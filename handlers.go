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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"regexp"
	"strconv"
	"bytes"
)

// Add default headers
func baseHandler(c *context, w http.ResponseWriter, r *http.Request) (int, error) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,HEAD,OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, Pragma, Expires, WWW-Authenticate")
	w.Header().Set("Cache-Control", "no-cache, no-storage, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "Sat, 26 Jul 1997 05:00:00 GMT")
	return 200, nil
}

func sessionHandler(c *context, w http.ResponseWriter, r *http.Request) (int, error) {

	sessionCookie, err := getSecureCookie(r, "mpindemo_session", c.App.Options.UseSecureCookie)

	if err != nil {
		createNewSession(c, w)
		return 200, nil
	}

	item, err := c.App.Store.Get(sessionCookie.Value)

	if err != nil {
		createNewSession(c, w)
		return 200, nil
	}

	c.SessionID = sessionCookie.Value
	setSecureCookie(w, &http.Cookie{Name: "mpindemo_session", Value: c.SessionID, MaxAge: 60 * 60 * 4}, c.App.Options.UseSecureCookie)
	c.LoggedUser = item.User
	log.Printf("D Setting logged user to %v", c.LoggedUser)
	c.App.Store.Put(c.SessionID, item)

	return 200, nil
}

func indexHandler(c *context, w http.ResponseWriter, r *http.Request) (int, error) {
	if r.URL.Path != "/" {
		return 404, errors.New("Page not found")
	}
	if s, err := checkAllowedMethods(r, w, "GET", "HEAD"); err != nil {
		return s, err
	}
	data := make(map[string]interface{})
	data["StaticURLBase"] = c.App.Options.StaticURLBase
	data["MpinJSURL"] = c.App.Options.MpinJSURL
	data["User"] = c.LoggedUser
	data["ClientSettingsURL"] = c.App.Options.ClientSettingsURL
	data["MobileAppFullURL"] = c.App.Options.MobileAppFullURL

	return renderTemplate(c.App, w, "index.tmpl", data)
}

// RPS sends request to RPA to verify user; extended verification can happen here
func verifyUserHandler(c *context, w http.ResponseWriter, r *http.Request) (int, error) {

	if s, err := checkAllowedMethods(r, w, "POST"); err != nil {
		return s, err
	}

	bufbody := new(bytes.Buffer)
	bufbody.ReadFrom(r.Body)
	buf := bufbody.Bytes()
	var rq verifyUserRequest
	var f interface{}
	err := json.Unmarshal(buf, &f)
	if err != nil {
		log.Printf("E %v %v Can not decode body as JSON", c.SessionID, "")
		return 400, errors.New("BAD REQUEST. INVALID JSON")
	}
	m := f.(map[string]interface{})
	rmk := []string{ "mpinId", "userId", "expireTime", "mobile", "activateKey", "activationCode", "resend", "deviceName", "userData" }
	for k, _ := range m {
		errflg := true
		for _ , j := range rmk {
			if k == j {
				errflg = false
				break
			}
		}
		if errflg {
			log.Printf("E %v %v Invalid data received. %v argument unnecessary", c.SessionID, "", k)
			return 400, errors.New("BAD REQUEST. INVALID KEY" )
		}
	}
	for _ ,j := range rmk[:4]  {
		if _, ok := m [j] ; !ok {
			log.Printf("E %v %v Invalid data received. %v argument missing", c.SessionID, "", j)
			return 400, errors.New("BAD REQUEST. INVALID KEY")
		}
	}
	if m["mobile"] == float64(1) {
		if _, ok := m ["activateKey"] ; !ok {
			log.Printf("E %v %v Invalid data received. activateKey argument missing", c.SessionID, "")
			return 400, errors.New("BAD REQUEST. INVALID KEY")
		}
	} else if m["mobile"] == float64(0) {
		if _, ok := m ["activationCode"] ; !ok {
			log.Printf("E %v %v Invalid data received. activationCode argument missing", c.SessionID, "")
			return 400, errors.New("BAD REQUEST. INVALID KEY")
		}
	}

	if err := decodeJSONRequest(buf, &rq); err != nil {
		log.Printf("E %v %v Can not decode body as JSON", c.SessionID, "")
		log.Printf("D %s {%v}", r.Body, c.SessionID)
		return 500, errors.New("BAD REQUEST. INVALID USER ID")
	}
	c.UserID = rq.UserID

	if len(rq.UserID) < 1 || len(rq.UserID) > 256 {
		log.Printf("E %v %v Invalid data received. userId argument invalid length", c.SessionID, rq.UserID)
		return 403, errors.New("BAD REQUEST. INVALID USER ID")
	} else if regexp.MustCompile("[^a-zA-Z0-9 -/:-@[-`{-~]").Match([]byte(rq.UserID)) {
		log.Printf("E %v %v Invalid data received. userId argument contains invalid characters", c.SessionID, rq.UserID)
		return 403, errors.New("BAD REQUEST. INVALID USER ID")
	}

	if regexp.MustCompile("[^0-9a-fA-F]").Match([]byte(rq.MpinID)){
		log.Printf("E %v %v Invalid data received. mpinId argument contains invalid characters", c.SessionID, rq.UserID)
		return 400, errors.New("BAD REQUEST. INVALID MPIN ID")
	}

	if len(rq.ExpireTime) != 20 {
		log.Printf("E %v %v Invalid data received. expireTime argument invalid length", c.SessionID, rq.UserID)
		return 400, errors.New("BAD REQUEST. INVALID EXPIRE TIME")
	} else if regexp.MustCompile("[^-0-9TZ:]").Match([]byte(rq.ExpireTime)){
		log.Printf("E %v %v Invalid data received. expireTime argument contains invalid characters", c.SessionID, rq.UserID)
		return 400, errors.New("BAD REQUEST. INVALID EXPIRE TIME")
	}

	if rq.Mobile == 1 {
		if len(rq.ActivateKey) != 0 && len(rq.ActivateKey) != 64 {
			log.Printf("E %v %v Invalid data received. activateKey argument invalid length", c.SessionID, rq.UserID)
			return 400, errors.New("BAD REQUEST. INVALID ACTIVATEKEY")
		} else if regexp.MustCompile("[^0-9a-fA-F]").Match([]byte(rq.ActivateKey)){
			log.Printf("E %v %v Invalid data received. activateKey argument contains invalid characters", c.SessionID, rq.UserID)
			return 400, errors.New("BAD REQUEST. INVALID ACTIVATEKEY")
		}
	}else if rq.Mobile == 0 {
		if len(strconv.Itoa(rq.ActivationCode)) > 12  {
			log.Printf("E %v %v Invalid data received. activationCode argument invalid length", c.SessionID, rq.UserID)
			return 400, errors.New("BAD REQUEST. INVALID ACTIVATIONCODE")
		}
	}

	if rq.Mobile != 0 && rq.Mobile != 1 {
		log.Printf("E %v %v Invalid data received. mobile argument invalid number", c.SessionID, rq.UserID)
		return 400, errors.New("BAD REQUEST. INVALID MOBILE")
	}

	if s, err := verifyUser(c, r, &rq); err != nil {
		if s == 403 {
			return s, errors.New("BAD REQUEST. INVALID USER ID")
		} else {
			return s, errors.New("")
		}
	}

	resp := verifyUserResponse{c.App.Options.ForceActivate}

	w.Header().Set("Content-Type", "application/json")
	if err := encodeJSONResponse(w, resp); err != nil {
		return 500, errors.New("Failed to encode response")
	}

	return 200, nil
}

// RPA authenticate method
func authenticateUserHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {

	if s, err := checkAllowedMethods(r, w, "POST"); err != nil {
		return s, err
	}

	bufbody := new(bytes.Buffer)
	bufbody.ReadFrom(r.Body)
	buf := bufbody.Bytes()
	var rq authRPARequest

	var f interface{}
	error := json.Unmarshal(buf, &f)
	if error != nil {
		log.Printf("E %v %v Can not decode body as JSON", c.SessionID, "")
		return 400, errors.New("Failed to encode response")
	}

	m := f.(map[string]interface{})

	for k, _ := range m {
		if k == "mpinResponse"{
			break
		}
		log.Printf("E %v %v Invalid data received. %v argument unnecessary" , c.SessionID, "", k)
		return 400, errors.New("BAD REQUEST. INVALID KEY" )
	}
	if _, ok := m ["mpinResponse"] ; !ok {
		log.Printf("E %v %v Invalid data received. mpinResponse argument missing" , c.SessionID, "")
		return 400, errors.New("BAD REQUEST. INVALID KEY")
	}

	rm := m["mpinResponse"].(map[string]interface{})
	for k, _ := range rm {
		errflg := true
		if k == "authOTT" || k == "version" || k == "pass" {
			errflg = false
		}
		if errflg {
			log.Printf("E %v %v Invalid data received. %v argument unnecessary", c.SessionID, "", k)
			return 400, errors.New("BAD REQUEST. INVALID KEY")
		}
	}
	if _, ok := rm ["authOTT"] ; !ok {
		log.Printf("E %v %v Invalid data received. authOTT argument missing", c.SessionID, "")
		return 400, errors.New("BAD REQUEST. INVALID KEY")
	}

	if err := decodeJSONRequest(buf, &rq); err != nil {
		log.Printf("E %v %v Can not decode body as JSON", c.SessionID, "")
		log.Printf("D %s {%v}", r.Body, c.SessionID)
		return 400, err
	}

	if len(rq.MpinResponse.AuthOTT) != 64  {
		log.Printf("E %v %v Invalid data received. authOTT argument invalid length", c.SessionID, "")
		return 400, errors.New("BAD REQUEST. AUTH OTT")
	} else if regexp.MustCompile("[^0-9a-fA-F]").Match([]byte(rq.MpinResponse.AuthOTT)){
		log.Printf("E %v %v Invalid data received. authOTT argument contains invalid characters", c.SessionID, "")
		return 400, errors.New("BAD REQUEST. AUTH OTT")
	}

	userID, message, status := c.App.Authenticate(c, rq.MpinResponse.AuthOTT)

	c.App.LoginResult(c, userID, rq.MpinResponse.AuthOTT, status, message)

	w.Header().Set("Content-Type", "application/json")

	if c.App.Options.RequestOTP {
		var ret authOTPResponse
		ret.TTLSeconds = 64
		ret.NowTime = time.Now().Unix() * 1000
		ret.ExpireTime = ret.NowTime + ret.TTLSeconds*1000
		if err := encodeJSONResponse(w, &ret); err != nil {
			return 500, errors.New("Failed to encode response")
		}
	} else {
		var ret authRPAResponse
		ret.SomeUserData = "This will be handled by onSuccessLogin handler."
		ret.UserId = userID
		if err := encodeJSONResponse(w, &ret); err != nil {
			return 500, errors.New("Failed to encode response")
		}
	}
	return status, errors.New(message)
}

// RPA activate user
func activateHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {
	if s, err := checkAllowedMethods(r, w, "GET", "POST"); err != nil {
		return s, err
	}
	params, err := verifySignature(c, r)
	if err != nil {
		return 500, err
	}

	if r.Method == "POST" && params.IsValid {

		if err = c.App.ActivateUser(c, params.Identity, params.ActivateKey); err == nil {
			params.Activated = true
		}
	}

	data := make(map[string]interface{})
	data["StaticURLBase"] = c.App.Options.StaticURLBase
	data["IsValid"] = params.IsValid
	data["Activated"] = params.Activated
	data["UserID"] = params.UserID
	data["HumanIssued"] = params.HumanIssued
	data["DeviceName"] = params.DeviceName
	data["ErrorMessage"] = params.ErrorMessage
	data["User"] = c.LoggedUser

	renderTemplate(c.App, w, "activate.tmpl", data)
	return 200, nil
}

func permitUserHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {
	if s, err := checkAllowedMethods(r, w, "GET"); err != nil {
		return s, err
	}
	// The revocation handler
	// When the RPS option RPAPermitUserURL is set
	// It will make a request for validating the identity
	// Before giving the time permit share to the client

	w.Header().Set("Content-Type", "application/json")

	// If you return 403 it will show Unauthorized message inside the PinPad
	// self.set_status(403)

	return 200, nil
}

func protectedHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {
	if s, err := checkAllowedMethods(r, w, "GET"); err != nil {
		return s, err
	}
	if len(c.LoggedUser) < 1 {
		http.Redirect(w, r, "/", 301)
	} else {
		protectdePage := strings.TrimLeft(r.URL.Path, "/protected/")
		var templateName string
		if len(protectdePage) < 1 {
			templateName = "protected.tmpl"
		} else {
			templateName = fmt.Sprintf("protected_%v.tmpl", protectdePage)
		}
		data := make(map[string]interface{})
		data["Welcome"] = false
		data["User"] = c.LoggedUser
		data["StaticURLBase"] = c.App.Options.StaticURLBase

		renderTemplate(c.App, w, templateName, data)
	}
	return 200, nil
}

func aboutHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {
	if s, err := checkAllowedMethods(r, w, "GET"); err != nil {
		return s, err
	}
	http.Redirect(w, r, "http://www.certivox.com/m-pin/", 301)
	return 301, nil
}

func logoutHandler(c *context, w http.ResponseWriter, r *http.Request) (status int, err error) {
	if s, err := checkAllowedMethods(r, w, "GET", "POST", "OPTIONS"); err != nil {
		return s, err
	}

	if r.Method == "GET" {
		_, err := c.App.Store.Get(c.SessionID)
		if err == nil {
			c.App.Store.Delete(c.SessionID)
		}
		deleteCookie(w, "mpindemo_session")
		http.Redirect(w, r, "/", 301)
		return 301, nil
	}

	if r.Method == "OPTIONS" {
		return 200, nil
	}

	decoder := json.NewDecoder(r.Body)
	var data struct {
		SessionID string `json:"sessionToken"`
		UserID    string `json:"userId"`
	}
	err = decoder.Decode(&data)
	if err != nil {
		log.Printf("E %v %v Can not decode body as JSON", c.SessionID, "")
		log.Printf("D %s", r.Body)
		log.Printf("E %v %v %v", c.SessionID, "", err)
		return 400, errors.New("BAD REQUEST. INVALID JSON")
	}
	log.Printf("D Logout request. Session token: %v", data.SessionID)

	item, err := c.App.Store.Get(data.SessionID)
	c.UserID = data.UserID
	if item.User != data.UserID {
		log.Printf("E %v %v The logged user %v does not match the requested user %v", c.SessionID, data.UserID, item.User, data.UserID)
		return 400, errors.New("Logout failed")
	}
	if err == nil {
		c.App.Store.Delete(data.SessionID)
	}
	return 200, nil

}
