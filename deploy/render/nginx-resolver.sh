#!/bin/sh
# nginx re-resolves the API hostname at runtime (Render's edge IPs can change), which needs an
# explicit resolver: use the container's own DNS server.
ns=$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)
case "$ns" in *:*) ns="[$ns]" ;; esac
echo "resolver ${ns:-8.8.8.8} valid=60s ipv6=off;" > /etc/nginx/conf.d/00-resolver.conf
