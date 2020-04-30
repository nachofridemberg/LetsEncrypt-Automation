#!/bin/bash
echo "server localhost" > file2
echo "zone DOMAIN" >> file2
echo "update delete _acme-challenge.DOMAIN >> file2
echo "send" >> file2
nsupdate -k Kremote.*.key file2
