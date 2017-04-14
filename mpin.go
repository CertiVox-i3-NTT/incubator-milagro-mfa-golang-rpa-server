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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"./ldap"
	"log"
	"net/http"
	"strings"
	"time"
)

// Verify user helpers

type verifyUserRequest struct {
	MpinID      string `json:"mpinId"`
	UserID      string `json:"userId"`
	ExpireTime  string `json:"expireTime"`
	ActivateKey string `json:"activateKey"`
	ActivationCode int   `json:"activationCode"`
	Mobile      int    `json:"mobile"`
}

type verifyUserResponse struct {
	ForceActivate bool `json:"forceActivate"`
}

func verifyUser(c *context, r *http.Request, rq *verifyUserRequest) (status int, err error) {

	var baseURL string
	if c.App.Options.VerifyIdentityURL[0] == '/' && len(r.Header["RPS-BASE-URL"]) > 0 {
		baseURL = fmt.Sprintf(
			"%v/%v", strings.TrimRight(r.Header["RPS-BASE-URL"][0], "/"),
			strings.TrimLeft(c.App.Options.VerifyIdentityURL, "/"))
	} else {
		baseURL = c.App.Options.VerifyIdentityURL
	}

	if c.App.Options.ForceActivate {
		log.Println("D forceActivate option set! User activated without verification!")
	} else {
		if c.App.Options.LDAPVerify {
			var ldapconnection *ldap.Conn
			addr := fmt.Sprintf("%s:%d", c.App.Options.LDAPServer, c.App.Options.LDAPPort)
			if !c.App.Options.LDAPUseTLS {
				ldapconnection, err = ldap.Dial("tcp", addr)
				if err != nil {
					log.Printf("E %v %v Remote LDAP connection failed: %v", c.SessionID, rq.UserID, err)
					return 500, err
				}
			} else {
				tlsConfig := c.App.tlsConfig
				tlsConfig.ServerName = c.App.Options.LDAPServer
				ldapconnection, err = ldap.DialTLS("tcp", addr, c.App.tlsConfig)
				if err != nil {
					log.Printf("E %v %v Remote LDAP connection failed: %v", c.SessionID, rq.UserID, err)
					return 500, err
				}
			}
			defer ldapconnection.Close()

			if c.App.Options.LDAPBindDN != "" && c.App.Options.LDAPBindPWD != "" {
				err = ldapconnection.Bind(c.App.Options.LDAPBindDN, c.App.Options.LDAPBindPWD)
				if err != nil {
					log.Printf("E %v %v Bind failed: %v", c.SessionID, rq.UserID, err)
					return 500, err
				}
			}

			ldapFilter := fmt.Sprintf(c.App.Options.LDAPFilter, ldap.EscapeFilter(rq.UserID))
			searchRequest := ldap.NewSearchRequest(c.App.Options.LDAPBaseDN, ldap.ScopeWholeSubtree, 
				ldap.NeverDerefAliases, 
				1, 
				600, 
				true, 
				ldapFilter, nil, nil)
			result, err := ldapconnection.Search(searchRequest)
			if err != nil {
				log.Printf("E %v %v Not Found Entry: %v", c.SessionID, rq.UserID, err)
				return 500, err
			} else if len(result.Entries) == 0 {
				err = errors.New("Not Found Entry")
				log.Printf("W %v %v %v", c.SessionID, rq.UserID, err)
				if !c.App.Options.LDAPVerifyShow {
					return 200, nil
				} else {
					return 403, err
				}
			}
		}

		validateURL := ""
		activationCode := 0

		if(rq.ActivateKey != "") {
			validateURL = fmt.Sprintf("%v?i=%v&e=%v&s=%v", baseURL, rq.MpinID, rq.ExpireTime, rq.ActivateKey)
			log.Printf("D Sending activation email for user %v: %v {%v}", rq.UserID, activationCode, c.SessionID)
			var deviceName string
			if rq.Mobile == 0 {
				deviceName = "PC"
			} else {
				deviceName = "Mobile"
			}
			if err := c.App.Mail(rq.UserID, deviceName, validateURL, c.App.Options); err != nil {
				log.Printf("W %v %v Failed to send mail", c.SessionID, rq.UserID)
			}

		}
		if(rq.ActivationCode != 0) {
			activationCode = rq.ActivationCode
				log.Printf("D Sending activation email for user %v: %v {%v}", rq.UserID, activationCode, c.SessionID)
			deviceName := "PC"

			if err := sendEMpinActivationMail(rq.UserID, deviceName, activationCode, c.App.Options); err != nil {
				log.Printf("W %v %v Failed to send mail: %v", c.SessionID, rq.UserID, err)
			}
		}
	}
	return 200, nil
}

// Authenticate to RPA

type authRPARequest struct {
	MpinResponse struct {
		AuthOTT string `json:"authOTT"`
	} `json:"mpinResponse"`
}

type authOTPResponse struct {
	ExpireTime int64 `json:"expireTime"`
	TTLSeconds int64 `json:"ttlSeconds"`
	NowTime    int64 `json:"nowTime"`
}

type authRPAResponse struct {
	SomeUserData string `json:"someUserData"`
	UserId string `json:"userId"`
}

// Authenticate to RPS

type authRPSRequest struct {
	AuthOTT   string `json:"authOTT"`
	LogoutData struct {
		SessionToken string `json:"sessionToken"`
	} `json:"logoutData"`
}

type authRPSResponse struct {
	Status  int    `json:"status"`
	UserID  string `json:"userId"`
	Message string `json:"message"`
}

func authenticateToRPS(c *context, authOTT string) (userID, message string, status int) {

	url := fmt.Sprintf("%v://%v/authenticate", c.App.Options.RPSSchema, c.App.Options.RPSHost)
	var req authRPSRequest
	req.AuthOTT = authOTT
	req.LogoutData.SessionToken = c.SessionID

	var resp authRPSResponse

	if err := c.App.Fetch(c.App, url, "POST", &req, &resp); err != nil {
		log.Printf("E %v %v %v", c.SessionID, "", err)
		log.Printf("E %v %v Invalid data from RPS", c.SessionID, "")
		status = resp.Status
		message = "Server error"
		return
	}
	status = resp.Status
	message = resp.Message
	userID = resp.UserID
	c.UserID = resp.UserID
	return
}

type sendLoginResultReq struct {
	AuthOTT    string `json:"authOTT"`
	Status     int    `json:"status"`
	Message    string `json:"message"`
	LogoutData struct {
		SessionToken string `json:"sessionToken"`
		UserID       string `json:"userId"`
	} `json:"logoutData"`
}

// Activate

type signature struct {
	IsValid      bool
	Identity     string
	ErrorMessage string
	UserID       string
	Issued       string
	HumanIssued  string
	Activated    bool
	DeviceName   string
	ActivateKey  string
}

func verifySignature(c *context, r *http.Request) (s signature, err error) {

	if err := r.ParseForm(); err != nil {
		log.Printf("E %v %v %v", c.SessionID, "", err)
		return s, err
	}

	s.Identity = getArgument(r, "i", "")[0]
	expires := getArgument(r, "e", "")[0]
	s.ActivateKey = getArgument(r, "s", "")[0]
	log.Printf("D /mpinActivate request for identity: %v {%v}", s.Identity, c.SessionID)

	b, err := hex.DecodeString(s.Identity)
	if err != nil {
		log.Printf("E %v %v %v", c.SessionID, "", err)
		return s, err
	}

	var data struct {
		UserID string `json:"userID"`
		Issued string `json:"issued"`
		Mobile int    `json:"mobile"`
	}

	if err := json.Unmarshal(b, &data); err != nil {
		log.Printf("E %v %v %v", c.SessionID, "", err)
		return s, err
	}
	c.UserID = data.UserID
	t, err := time.Parse("2006-01-02 15:04:05", data.Issued)
	if err != nil {
		log.Printf("E %v %v %v", c.SessionID, data.UserID, err)
		return s, err
	}
	if len(data.UserID) > 0 && err == nil {
		s.UserID = data.UserID
		s.Issued = data.Issued

		s.HumanIssued = t.Format(time.RFC822Z)

		if expires < time.Now().UTC().Format(time.RFC3339) {
			s.IsValid = false
			s.ErrorMessage = "Link expired"
		} else {
			s.IsValid = true
			s.ErrorMessage = ""
		}

		if data.Mobile != 0 {
			s.DeviceName = "Mobile"
		} else {
			s.DeviceName = "PC"
		}
	} else {
		log.Printf("E %v %v /mpinActivate: Invalid IDENTITY %v", c.SessionID, data.UserID, s.Identity)
		s.IsValid = false
		s.ErrorMessage = "Invalid identity"
		s.DeviceName = ""
		s.Issued = ""
	}
	log.Printf("D siganture is %+v {%v}", s, c.SessionID)
	if !s.IsValid {
		err = errors.New(s.ErrorMessage)
	}
	return

}

func activateUserRPS(c *context, identity, activateKey string) (err error) {

	url := fmt.Sprintf("%v://%v/user/%v", c.App.Options.RPSSchema, c.App.Options.RPSHost, identity)
	var q struct {
		ActivateKey string `json:"activateKey"`
	}
	q.ActivateKey = activateKey
	if err = c.App.Fetch(c.App, url, "POST", &q, nil); err != nil {
		log.Printf("E %v %v URL: %v: Error: %v", c.SessionID, "", url, err)
	}
	return
}

func sendLoginResult(c *context, userID string, authOTT string, status int, message string) (err error) {

	if status != 200 {
		return
	}

	// The Revocation check based on userId or mpinId can be performed here
	// The new status can be
	// 200 - Login successful
	// 401 - Invalid PIN
	// 403 - User not authorized. Login denied without deleting the client's token.
	// 408 - The authentication has been expired.
	// 410 - Login denied permanently. Will delete the client's token.

	// Example:

	// if strings.HasSuffix(resp.userId, "@certivox.com") || strings.HasSuffix(resp.userId, "@miracl.com") {
	//  status = 403
	// }

	// If the RPS waitLoginResult option is set, /loginResult request must be made
	// It can contain logoutData and logoutURL for mobile Logout functionality

	url := fmt.Sprintf("%v://%v/loginResult", c.App.Options.RPSSchema, c.App.Options.RPSHost)
	var req sendLoginResultReq
	req.AuthOTT = authOTT
	req.Status = status
	req.Message = message
	req.LogoutData.SessionToken = c.SessionID
	req.LogoutData.UserID = userID

	c.App.Fetch(c.App, url, "POST", &req, nil)

	if status == 200 {

		if len(c.SessionID) > 0 {
			var item session
			item.User = userID
			log.Printf("D Authenticated user %v {%v}", item.User, c.SessionID)
			c.App.Store.Put(c.SessionID, item)
		}
	}
	return
}
