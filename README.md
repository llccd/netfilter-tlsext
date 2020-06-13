# xt_tlsext

A kernel module/iptables extension for matching extension in TLS handshake  
modified from (https://github.com/Lochnair/xt_tls)

Usage
=====

```
iptables -t mangle -I POSTROUTING -p tcp --dport 443 -m tlsext --handshake-type 1 --has-ext 43
```
This will match TLS1.3 Client Hello.  
```
iptables -t mangle -I POSTROUTING -p tcp --dport 443 -m tlsext --handshake-type 1 ! --has-ext 0
```
This will match Client Hello without SNI.
