
# Automatic Renewal  letsencript certificates #

Description: The customer needed to automate the letsencrypt task.

Also of the certificate download, the task has required  spread the wildcard certificate between web servers and restart web servers.

This script had has developed for linux centos 7, python 2.7 and named dns.



Script plan:

```
1.  Renewal command for cerbot certificate

2.  Spread the certificate in the differents servers.
    a.  Transfer the certificate to web servers
    b.  Reboot the services
    c.  Check certificate using Urlib  

```

## List  of  service  to  update  #

| Number | Name                 | Operating system    | Sites                        |                             
| ---    | ---                  | ---                 | ---                             |
|   1    | server_name          | linux/win           | https://url                     |


## Previous Steps
------------------------------------------------------------------

1. Generate dns key
```
dnssec-keygen -a HMAC-SHA512 -b 512 -n HOST certbot
```
2. Replace constants like domain, and folders.


