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
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

type session struct {
	Expires time.Time
	User    string
}

type storage map[string]session

var mu sync.RWMutex
var gcCount int

func (s storage) Put(sessionID string, item session) (err error) {
	if item.Expires.IsZero() {
		item.Expires = time.Now().Add(time.Duration(4 * time.Hour))
	}
	mu.Lock()
	s[sessionID] = item
	gcCount++
	if gcCount >= 1000 {
		for k, v := range s {
			if v.Expires.Before(time.Now()) {
				delete(s, k)
			}
		}
		gcCount = 0
	}
	mu.Unlock()
	return
}

func (s storage) Get(sessionID string) (item session, err error) {
	mu.RLock()
	item, ok := s[sessionID]
	mu.RUnlock()
	if !ok {
		return session{}, errors.New("SessionID not found")
	}
	if item.Expires.Before(time.Now()) {
		mu.Lock()
		delete(s, sessionID)
		mu.Unlock()
		return session{}, errors.New("SessionID expired")
	}
	return item, nil
}

func (s storage) Delete(sessionID string) {
	mu.Lock()
	delete(s, sessionID)
	mu.Unlock()
}

type app struct {
	Store        storage
	Options      *options
	RpsProxy     *httputil.ReverseProxy
	Fetch        func(a *app, url string, method string, q interface{}, d interface{}) (err error)
	Mail         func(userID, deviceName, validateURL string, o *options) (err error)
	Authenticate func(*context, string) (string, string, int)
	LoginResult  func(*context, string, string, int, string) error
	ActivateUser func(*context, string, string) error
	Templates    map[string]*template.Template
	tlsConfig    *tls.Config
}

type context struct {
	SessionID  string
	LoggedUser string
	App        *app
	UserID     string
}

func newApp() *app {
	var a app
	a.Store = make(storage)
	a.Options = getOptions()
	a.Fetch = fetchJSON
	a.Mail = sendActivationMail
	a.Authenticate = authenticateToRPS
	a.LoginResult = sendLoginResult
	a.ActivateUser = activateUserRPS

	rpsDirector := func(req *http.Request) {
		req.URL.Scheme = a.Options.RPSSchema
		req.URL.Host = a.Options.RPSHost
	}
	if a.Options.CACertFile == "" {
		a.RpsProxy = &httputil.ReverseProxy{Director: rpsDirector}
	} else {
		a.tlsConfig = loadCACerts(a.Options.CACertFile)
		transport := &http.Transport{TLSClientConfig: a.tlsConfig}
		a.RpsProxy = &httputil.ReverseProxy{Director: rpsDirector, Transport: transport}
	}
	a.Templates = loadTemplates(a.Options.TemplatesPath)

	return &a
}

type appMiddleware func(*context, http.ResponseWriter, *http.Request) (int, error)

type appHandler struct {
	AppContext *app
	Hs         []appMiddleware
}

func (ah appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	var c context
	c.App = ah.AppContext
        var status_tmp int
	c.UserID = ""

	for _, h := range ah.Hs {
		status, err := h(&c, w, r)
                status_tmp = status
		if err != nil && status >= 400 {
			log.Printf("E %v %v HTTP %d %v %v %v", c.SessionID, "", status, r.URL.Path, r.RemoteAddr, err)
			switch status {
			case http.StatusNotFound:
				http.NotFound(w, r)
			case http.StatusInternalServerError:
				http.Error(w, http.StatusText(status), status)
			case http.StatusBadRequest:
				http.Error(w, err.Error(), status)
			case http.StatusForbidden:
				http.Error(w, err.Error(), status)
			default:
				http.Error(w, http.StatusText(status), status)
			}
			return
		}
	}
        log.Printf("I %d %v %v %v %v %v", status_tmp, r.Method, r.URL.Path, r.RemoteAddr, c.SessionID, c.UserID)
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {

	app := newApp()

	chain := func(mws ...appMiddleware) appHandler {
		return appHandler{app, mws}
	}

	// Static file server
	http.Handle(app.Options.StaticURLBase, http.FileServer(http.Dir(app.Options.ResourcesBasePath)))
	http.Handle(app.Options.MobileAppFullURL, http.StripPrefix(app.Options.MobileAppFullURL, http.FileServer(http.Dir(app.Options.MobileAppPath))))

	// M-PIN handlers
	var rpsProxyHandler = func(c *context, w http.ResponseWriter, r *http.Request) (int, error) {
		c.App.RpsProxy.ServeHTTP(w, r)
		return 200, nil
	}
	http.Handle(fmt.Sprintf("/%s/", app.Options.RpsPrefix), chain(sessionHandler, rpsProxyHandler))
	http.Handle("/mpinVerify", chain(baseHandler, sessionHandler, verifyUserHandler))
	http.Handle("/mpinAuthenticate", chain(baseHandler, sessionHandler, authenticateUserHandler))
	http.Handle("/mpinActivate", chain(baseHandler, sessionHandler, activateHandler))
	http.Handle("/mpinPermitUser", chain(baseHandler, sessionHandler, permitUserHandler))

	// Application handlers
	http.Handle("/protected", chain(baseHandler, sessionHandler, protectedHandler))
	http.Handle("/about", chain(baseHandler, sessionHandler, aboutHandler))
	http.Handle("/logout", chain(baseHandler, sessionHandler, logoutHandler))

	http.Handle("/login", chain(baseHandler, sessionHandler, indexHandler))
	http.Handle("/", chain(baseHandler, sessionHandler, indexHandler))

	if !app.Options.EnableTLS {
		http.ListenAndServe(fmt.Sprintf("%v:%v", app.Options.Address, app.Options.Port), nil)
	} else {
		err := http.ListenAndServeTLS(fmt.Sprintf("%v:%v", app.Options.Address, app.Options.Port), app.Options.CertFile, app.Options.KeyFile, nil)
		if err != nil {
			log.Fatal(err)
		}
	}
}
