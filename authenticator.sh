#/bin/bash
echo "server localhost" > file
echo "zone DOMAIN" >> file
echo "update add _acme-challenge.DOMAIN 600 TXT "$CERTBOT_VALIDATION >> file
echo "send" >> file
nsupdate -k Kremote.*.key file

