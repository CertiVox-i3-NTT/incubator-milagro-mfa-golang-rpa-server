Go implementation of M-Pin demo
===============================

####Building

The demo does not have dependencies outside the standard lib. A normal ```go build``` is enough.


####Configuration options


The demo is configured with command line flags. Out of the box configuration should work with default mpin core installation on local machine (do not forget to stop the python demo, or change ports for it or this demo, as the defaults are the same).


The flags and their defaults can also be listed with '-h' flag. When not specified default is empty. Empty is false for boolean flags.

* `-address string` IP address to bind. By default the app binds all addresses.

* `-s` Enable TLS

* `-cert string (default "/etc/ssl/certs/ssl-cert-snakeoil.pem")` Path to public certificate file.

* `-key string (default "/etc/ssl/private/ssl-cert-snakeoil.key")` Path to certificate key file.


* `-client-settings-url string (default "/rps/clientSettings")` Client settings URL. By default client settings are pulled from RPS through the app proxy.


* `-cookie-secret string` Secret for creating cookies. For demo purposes the default is empty string.

* `-email-sender string`
 
  `-email-subject string (default "M-Pin demo: New user activation")`

  `-smtp-password string`
  
  `-smtp-port int (default 25)`
  
  `-smtp-server string`
  
  `-smtp-use-tls`
  
  `-smtp-user string`

     Email sending options. Not needed by default, as the application does not do extended validation (-force-activate flag is set)

* `-ldap-verify  (default false)` Check ID existing in LDAP

  `-ldap-verify-show  (default false)` Show result of searching ID in client

  `-ldap-server string`

  `-ldap-port int`

  `-ldap-dn string` Bind DN

  `-ldap-password string` Bind password

  `-ldap-basedn string`

  `-ldap-filter string  (default "(uid=%s)")` Search filter replaced %s with ID

  `-ldap-use-tls  (default false)`

* `-force-activate  (default true)` Force user activation without sending mail. For demo purposes user are automatically activated by default

* `-mobile-app-full-url string (default "/m/")` URL for HTML mobile app

* `-mobile-app-path string (default "/opt/mpin/mpin-3.5/mobile/")` Local system path for mobile app (files are not included in demo - existing M-pin installation is expected)

* `-mobile-support (default true)` Enable mobile support . By default mobile app is enabled.

*  `-pinpad-url string (default "https://mpin.certivox.net/v3/mpin.js")` URL for PIN pad to use.

* `-port int  (default 8005)` Default port to listen.

* `-request-otp` Request OTP. Off by default

* `-resources-base string (default: relative to executable path)` Base dir for static resources - where 'public' and 'templates' dirs are located . If not specified, executable current dir is taken at startup.

* `-rps-host string (default "127.0.0.1:8011")` RPS host. By default it is expected that RPS is running on local machine.

* `-rps-prefix string (default "rps")` Prefix for RPS proxy.

* `-rps-schema string (default "http")` Protocol schema for access to RPS.

* `-ca-cert file` Path to CA certificates file.

* `-secure-cookie` Use secure cookies for sessions. By default it is off, as secure cookies require secured connection.

* `-verify-identity-url string (default "http://localhost:8005/mpinActivate")` URL to verify identity. By default it is served by the demo itself on localhost.

####Running tests

For  ```sh test_full.sh``` and ```go run``` add ```-resources-base=.``` flag, as default is relative to binary.
