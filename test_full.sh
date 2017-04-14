#!/usr/bin/env bash
set -e
cd asn1-ber
go test -v
cd ..

ulimit -n 102400
go build -o new-mpin-rpa-go
./new-mpin-rpa-go -port 18005 &
go test -v
kill %1
