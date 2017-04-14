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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLoadTemplates0File(t *testing.T) {
	templates := loadTemplates("./test/empty")
	if len(templates) != 0 {
		t.Errorf("len(templates) = <%d> want <%d>", len(templates), 0)
	}
}

func TestLoadTemplates1File(t *testing.T) {
	templates := loadTemplates("./test/1file")
	if len(templates) != 1 {
		t.Errorf("len(templates) = <%d> want <%d>", len(templates), 1)
	}
	if _, ok := templates["index.tmpl"]; !ok {
		t.Error("index.tmpl should be loaded")
	}
}

func TestLoadTemplates2File(t *testing.T) {
	templates := loadTemplates("./test/2files")
	if len(templates) != 2 {
		t.Errorf("len(templates) = <%d> want <%d>", len(templates), 2)
	}
	if _, ok := templates["index.tmpl"]; !ok {
		t.Error("index.tmpl should be loaded")
	}
	if _, ok := templates["activate.tmpl"]; !ok {
		t.Error("activate.tmpl should be loaded")
	}
}

func TestLoadTemplatesLayoutError(t *testing.T) {
	envName := "RPA_TEST_LOAD_TEMPLATES_LAYOUT_ERROR"

	if os.Getenv(envName) == "1" {
		loadTemplates("[]")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoadTemplatesLayoutError")
	cmd.Env = append(os.Environ(), envName + "=1")
	stdout, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	errMessage := "syntax error in pattern"
	gotBytes, _ := ioutil.ReadAll(stdout)
	got := string(gotBytes)
	if !strings.HasSuffix(got[:len(got) - 1], errMessage) {
		t.Errorf("Unexpected log message. Got <%s> want <%s>", got[:len(got) - 1], errMessage)
	}

	err := cmd.Wait()
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Errorf("Process ran with err <%v> want exit status 1", err)
	}
}

func TestRenderTemplateExist(t *testing.T) {
	a := app{Templates: loadTemplates("./test/2files")}
	if len(a.Templates) != 2 {
		t.Errorf("len(a.Templates) = <%d> want <%d>", len(a.Templates), 2)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]interface{})
		data["MpinJSURL"] = "http://localhost/"
		data["User"] = "user"

		status, err := renderTemplate(&a, w, "index.tmpl", data)
		if err != nil {
			t.Error(err)
		}
		if status != 200 {
			t.Errorf("status = <%d> want <%d>", status, 200)
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

	contentType := "text/html; charset=utf-8"
	if res.Header.Get("Content-Type") != contentType {
		t.Errorf("Content-Type = <%s> want <%s>", res.Header.Get("Content-Type"), contentType)
	}

	expectBody := `
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>M-Pin demo</title>

<script type="text/javascript" src="http://localhost/"></script>

<script type="text/javascript"></script>



</head>
<body>
<div class="loggedInStatus">You are logged in as: user | <a href="/logout"> Log Out </a></div>

<h1>Welcome to the M-Pin System Demo</h1>

</body>
</html>
`
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	if string(body) != expectBody {
		t.Errorf("body = <%s> want <%s>", string(body), expectBody)
	}
}

func TestRenderTemplateNotExist(t *testing.T) {
	a := app{Templates: loadTemplates("./test/2files")}
	if len(a.Templates) != 2 {
		t.Errorf("len(a.Templates) = <%d> want <%d>", len(a.Templates), 2)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]interface{})

		status, err := renderTemplate(&a, w, "notExist.tmpl", data)
		errMessage := "The template notExist.tmpl does not exist."
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
		if status != 500 {
			t.Errorf("status = <%d> want <%d>", status, 500)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	_, err := http.Get(server.URL)
	if err != nil {
		t.Error(err)
	}
}

func TestRenderTemplateExecuteError(t *testing.T) {
	a := app{Templates: loadTemplates("./test/2files")}
	if len(a.Templates) != 2 {
		t.Errorf("len(a.Templates) = <%d> want <%d>", len(a.Templates), 2)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]interface{})
		data["MpinJSURL"] = "http://localhost/"
		data["User"] = "user"
		data["User2"] = "user"

		status, err := renderTemplate(&a, w, "activate.tmpl", data)
		errMessage := "html/template:activate.tmpl:7:12: no such template \"template error\""
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
		if status != 500 {
			t.Errorf("status = <%d> want <%d>", status, 500)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	_, err := http.Get(server.URL)
	if err != nil {
		t.Error(err)
	}
}

func TestLoadCACertsExist(t *testing.T) {
	tlsConfig := loadCACerts("./test/cacert/cacert.pem")
	if tlsConfig.RootCAs  == nil {
		t.Errorf("tlsConfig.RootCAs = <nil> want <not nil>")
	}
}

func TestLoadCACertsNotExistError(t *testing.T) {
	envName := "RPA_TEST_LOAD_CA_CERT_ERROR"

	if os.Getenv(envName) == "1" {
		loadCACerts("./test/cacert/notExist.pem")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoadCACertsNotExistError")
	cmd.Env = append(os.Environ(), envName + "=1")
	stdout, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	errMessage := "no such file or directory"
	gotBytes, _ := ioutil.ReadAll(stdout)
	got := string(gotBytes)
	if !strings.HasSuffix(got[:len(got) - 1], errMessage) {
		t.Errorf("Unexpected log message. Got <%s> want <%s>", got[:len(got) - 1], errMessage)
	}

	err := cmd.Wait()
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Errorf("Process ran with err <%v> want exit status 1", err)
	}
}

func TestLoadCACertsParseError(t *testing.T) {
	envName := "RPA_TEST_LOAD_CA_CERT_ERROR"

	if os.Getenv(envName) == "1" {
		loadCACerts("./test/cacert/caerr.pem")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoadCACertsParseError")
	cmd.Env = append(os.Environ(), envName + "=1")
	stdout, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	errMessage := "failed to parse CA certificate"
	gotBytes, _ := ioutil.ReadAll(stdout)
	got := string(gotBytes)
	if !strings.HasSuffix(got[:len(got) - 1], errMessage) {
		t.Errorf("Unexpected log message. Got <%s> want <%s>", got[:len(got) - 1], errMessage)
	}

	err := cmd.Wait()
	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Errorf("Process ran with err <%v> want exit status 1", err)
	}
}

func TestFetchJSONNotResponse(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		if r.Method != method {
			t.Errorf("method = <%s> want <%s>", r.Method, method)
		}

		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(&req)
		if err != nil {
			t.Error(err)
		}
		if req.RequestParam != requestValue {
			t.Errorf("requestParam = <%s> want <%s>", req.RequestParam, requestValue)
		}

		w.WriteHeader(399)
	}

	var q ReqestMessage
	q.RequestParam = requestValue
	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	err := fetchJSON(&a, server.URL, method, &q, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestFetchJSONResponse(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	responseValue := "responseValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}
	type ResponseMessage struct {
		ResponseParam string `json:"responseParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		if r.Method != method {
			t.Errorf("method = <%s> want <%s>", r.Method, method)
		}

		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(&req)
		if err != nil {
			t.Error(err)
		}
		if req.RequestParam != requestValue {
			t.Errorf("requestParam = <%s> want <%s>", req.RequestParam, requestValue)
		}

		var res ResponseMessage
		res.ResponseParam = responseValue
		enc := json.NewEncoder(w)
		err = enc.Encode(&res)
		if err != nil {
			t.Error(err)
		}
	}

	var q ReqestMessage
	var d ResponseMessage
	q.RequestParam = requestValue
	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	err := fetchJSON(&a, server.URL, method, &q, &d)
	if err != nil {
		t.Error(err)
	}
	if d.ResponseParam != responseValue {
		t.Errorf("responseParam = <%s> want <%s>", d.ResponseParam, responseValue)
	}
}

func TestFetchJSONRequestJsonError(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"

	handler := func(w http.ResponseWriter, r *http.Request) {
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	err := fetchJSON(&a, server.URL, method, handler, nil)
	errMessage := "json: unsupported type: func(http.ResponseWriter, *http.Request)"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

func TestFetchJSONRequestNewError(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	var q ReqestMessage
	q.RequestParam = requestValue
	err := fetchJSON(&a, "://", method, &q, nil)
	errMessage := "parse ://: missing protocol scheme"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

func TestFetchJSONRequestDoError(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	var q ReqestMessage
	q.RequestParam = requestValue
	err := fetchJSON(&a, "", method, &q, nil)
	errMessage := "Post : unsupported protocol scheme \"\""
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

func TestFetchJSONResponseStatusError(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		if r.Method != method {
			t.Errorf("method = <%s> want <%s>", r.Method, method)
		}

		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(&req)
		if err != nil {
			t.Error(err)
		}
		if req.RequestParam != requestValue {
			t.Errorf("requestParam = <%s> want <%s>", req.RequestParam, requestValue)
		}

		w.WriteHeader(http.StatusBadRequest)
	}

	var q ReqestMessage
	q.RequestParam = requestValue
	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	err := fetchJSON(&a, server.URL, method, &q, nil)
	errMessage := "Error code 400"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

func TestFetchJSONResponseJsonError(t *testing.T) {
	o := options{CACertFile: ""}
	a := app{Options: &o}
	method := "POST"
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}
	type ResponseMessage struct {
		ResponseParam string `json:"responseParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		if r.Method != method {
			t.Errorf("method = <%s> want <%s>", r.Method, method)
		}

		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(&req)
		if err != nil {
			t.Error(err)
		}
		if req.RequestParam != requestValue {
			t.Errorf("requestParam = <%s> want <%s>", req.RequestParam, requestValue)
		}

		fmt.Fprint(w, "")
	}

	var q ReqestMessage
	var d ResponseMessage
	q.RequestParam = requestValue
	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	err := fetchJSON(&a, server.URL, method, &q, &d)
	errMessage := "EOF"
	if err == nil || err.Error() != errMessage {
		t.Errorf("err = <%s> want <%s>", err, errMessage)
	}
}

func TestGetArgumentDefault(t *testing.T) {
	requestParam := "requestParam"
	defaultValue := "defaultValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			t.Error(err)
		}
		args := getArgument(r, requestParam, defaultValue)
		if len(args) != 1 {
			t.Errorf("len(args) = <%d> want <%d>", len(args), 1)
		}
		if args[0] != defaultValue {
			t.Errorf("args[0] = <%s> want <%s>", args[0], defaultValue)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	_, err := http.PostForm(server.URL, url.Values{})
	if err != nil {
		t.Error(err)
	}
}

func TestGetArgumentArg1(t *testing.T) {
	requestParam := "requestParam"
	requestValue := "requestValue"
	defaultValue := "defaultValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			t.Error(err)
		}
		args := getArgument(r, requestParam, defaultValue)
		if len(args) != 1 {
			t.Errorf("len(args) = <%d> want <%d>", len(args), 1)
		}
		if args[0] != requestValue {
			t.Errorf("args[0] = <%s> want <%s>", args[0], requestValue)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	values := url.Values{}
	values.Add(requestParam, requestValue)
	req, err := http.NewRequest("POST", server.URL, strings.NewReader(values.Encode()))
	if err != nil {
		t.Error(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
}

func TestGetArgumentArg2(t *testing.T) {
	requestParam := "requestParam"
	requestValue1 := "requestValue1"
	requestValue2 := "requestValue2"
	defaultValue := "defaultValue"

	handler := func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			t.Error(err)
		}
		args := getArgument(r, requestParam, defaultValue)
		if len(args) != 2 {
			t.Errorf("len(args) = <%d> want <%d>", len(args), 2)
		}
		if args[0] != requestValue1 {
			t.Errorf("args[0] = <%s> want <%s>", args[0], requestValue1)
		}
		if args[1] != requestValue2 {
			t.Errorf("args[1] = <%s> want <%s>", args[1], requestValue2)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	values := url.Values{}
	values.Add(requestParam, requestValue1)
	values.Add(requestParam, requestValue2)
	req, err := http.NewRequest("POST", server.URL, strings.NewReader(values.Encode()))
	if err != nil {
		t.Error(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
}

func TestDecodeJSONRequest(t *testing.T) {
	requestValue := "requestValue"
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		defer r.Body.Close()

		bufbody := new(bytes.Buffer)
		bufbody.ReadFrom(r.Body)
		buf := bufbody.Bytes()

		err := decodeJSONRequest(buf, &req)
		if err != nil {
			t.Error(err)
		}
		if req.RequestParam != requestValue {
			t.Errorf("requestParam = <%s> want <%s>", req.RequestParam, requestValue)
		}
	}

	var q ReqestMessage
	q.RequestParam = requestValue
	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	body, err := json.Marshal(q)
	if err != nil {
		t.Error(err)
	}
	req, err := http.NewRequest("POST", server.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Error(err)
	}
	_, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
}

func TestDecodeJSONRequestJsonError(t *testing.T) {
	type ReqestMessage struct {
		RequestParam string `json:"requestParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req ReqestMessage

		defer r.Body.Close()

		bufbody := new(bytes.Buffer)
		bufbody.ReadFrom(r.Body)
		buf := bufbody.Bytes()
		err := decodeJSONRequest(buf, &req)
		errMessage := "BAD REQUEST. INVALID JSON"
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	_, err := http.PostForm(server.URL, url.Values{})
	if err != nil {
		t.Error(err)
	}
}

func TestEncodeJSONResponse(t *testing.T) {
	responseValue := "responseValue"
	type ResponseMessage struct {
		ResponseParam string `json:"responseParam"`
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		var res ResponseMessage
		res.ResponseParam = responseValue
		err := encodeJSONResponse(w, &res)
		if err != nil {
			t.Error(err)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	res, err := http.PostForm(server.URL, url.Values{})
	if err != nil {
		t.Error(err)
	}
	var d ResponseMessage
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&d)
	if d.ResponseParam != responseValue {
		t.Errorf("responseParam = <%s> want <%s>", d.ResponseParam, responseValue)
	}
}

func TestEncodeJSONResponseJsonError(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		err := encodeJSONResponse(w, httptest.NewServer)
		errMessage := "json: unsupported type: func(http.Handler) *httptest.Server"
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	http.PostForm(server.URL, url.Values{})
}

func TestCheckAllowedMethodsAllow1(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		status, err := checkAllowedMethods(r, w, "POST")
		if err != nil {
			t.Error(err)
		}
		if status != 200 {
			t.Errorf("status = <%d> want <%d>", status, 0)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, err := http.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Error(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	if len(res.Header["Access-Control-Allow-Methods"]) != 1 {
		t.Errorf("len(Access-Control-Allow-Methods) = <%d> want <%d>", len(res.Header["Access-Control-Allow-Methods"]), 1)
	}
	if res.Header["Access-Control-Allow-Methods"][0] != "POST" {
		t.Errorf("Access-Control-Allow-Methods[0] = <%s> want <%s>", res.Header["Access-Control-Allow-Methods"][0], "POST")
	}
}

func TestCheckAllowedMethodsAllow2(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		status, err := checkAllowedMethods(r, w, "GET", "POST")
		if err != nil {
			t.Error(err)
		}
		if status != 200 {
			t.Errorf("status = <%d> want <%d>", status, 0)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, err := http.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Error(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	if len(res.Header["Access-Control-Allow-Methods"]) != 1 {
		t.Errorf("len(Access-Control-Allow-Methods) = <%d> want <%d>", len(res.Header["Access-Control-Allow-Methods"]), 1)
	}
	if res.Header["Access-Control-Allow-Methods"][0] != "GET,POST" {
		t.Errorf("Access-Control-Allow-Methods[0] = <%s> want <%s>", res.Header["Access-Control-Allow-Methods"][0], "GET,POST")
	}
}

func TestCheckAllowedMethodsAllow0(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		status, err := checkAllowedMethods(r, w)
		errMessage := "Method not allowed"
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
		if status != 405 {
			t.Errorf("status = <%d> want <%d>", status, 405)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, err := http.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Error(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	if len(res.Header["Access-Control-Allow-Methods"]) != 1 {
		t.Errorf("len(Access-Control-Allow-Methods) = <%d> want <%d>", len(res.Header["Access-Control-Allow-Methods"]), 1)
	}
	if res.Header["Access-Control-Allow-Methods"][0] != "" {
		t.Errorf("Access-Control-Allow-Methods[0] = <%s> want <%s>", res.Header["Access-Control-Allow-Methods"][0], "")
	}
}

func TestCheckAllowedMethodsNotAllow(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		status, err := checkAllowedMethods(r, w, "GET")
		errMessage := "Method not allowed"
		if err == nil || err.Error() != errMessage {
			t.Errorf("err = <%s> want <%s>", err, errMessage)
		}
		if status != 405 {
			t.Errorf("status = <%d> want <%d>", status, 405)
		}
	}

	server := httptest.NewServer(
		http.HandlerFunc(handler),
	)
	defer server.Close()
	req, err := http.NewRequest("POST", server.URL, nil)
	if err != nil {
		t.Error(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Error(err)
	}
	if len(res.Header["Access-Control-Allow-Methods"]) != 1 {
		t.Errorf("len(Access-Control-Allow-Methods) = <%d> want <%d>", len(res.Header["Access-Control-Allow-Methods"]), 1)
	}
	if res.Header["Access-Control-Allow-Methods"][0] != "GET" {
		t.Errorf("Access-Control-Allow-Methods[0] = <%s> want <%s>", res.Header["Access-Control-Allow-Methods"][0], "GET")
	}
}
