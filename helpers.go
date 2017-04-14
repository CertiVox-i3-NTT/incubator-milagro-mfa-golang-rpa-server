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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

func loadTemplates(templatePath string) map[string]*template.Template {

	templates := make(map[string]*template.Template)

	layouts, err := filepath.Glob(templatePath + "/layout/*.tmpl")
	if err != nil {
		log.Fatal(err)
	}

	includes, err := filepath.Glob(templatePath + "/include/*.tmpl")
	if err != nil {
		log.Fatal(err)
	}

	for _, layout := range layouts {
		name := filepath.Base(layout)
		files := append(includes, layout)
		templates[name] = template.Must(template.ParseFiles(files...))
		log.Printf("D Loaded template %v from %v", name, layout)
	}

	return templates
}

func renderTemplate(a *app, w http.ResponseWriter, name string, data interface{}) (status int, err error) {

	tmpl, ok := a.Templates[name]
	if !ok {
		return 500, fmt.Errorf("The template %s does not exist.", name)
	}

	buff := bytes.NewBufferString("")

	if err = tmpl.ExecuteTemplate(buff, "base", data); err != nil {
		return 500, err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buff.Bytes())
	return 200, err
}

func loadCACerts(caCertPath string) *tls.Config {
	caCert, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		log.Fatal("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{RootCAs: caCertPool}
	return tlsConfig
}

func fetchJSON(a *app, url string, method string, q interface{}, d interface{}) (err error) {
	payload, err := json.Marshal(q)
	if err != nil {
		return
	}
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return
	}

	var client *http.Client
	if a.Options.CACertFile == "" {
		client = &http.Client{}
	} else {
		transport := &http.Transport{TLSClientConfig: a.tlsConfig}
		client = &http.Client{Transport: transport}
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode > 399 {
		return fmt.Errorf("Error code %v", resp.StatusCode)
	}
	if d == nil {
		return
	}
	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(d); err != nil {
		return err
	}
	return nil
}

func getArgument(r *http.Request, key, dflt string) []string {
	value, ok := r.Form[key]
	if !ok {
		log.Printf("D No %v argument, returning default: %v", key, dflt)
		return []string{dflt}
	}
	return value
}

func decodeJSONRequest(r []byte, v interface{}) error {
	err := json.Unmarshal(r, &v)
	if err != nil {
		return errors.New("BAD REQUEST. INVALID JSON")
	}
	return nil
}

func encodeJSONResponse(w http.ResponseWriter, v interface{}) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(v)
}

func checkAllowedMethods(r *http.Request, w http.ResponseWriter, methods ...string) (status int, err error) {
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	for _, m := range methods {
		if r.Method == m {
			return 200, err
		}
	}
	return 405, errors.New("Method not allowed")
}
