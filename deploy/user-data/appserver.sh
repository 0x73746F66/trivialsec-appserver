#!/bin/bash -xe
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
/usr/sbin/nginx
runuser -l ec2-user -c '/home/ec2-user/.local/bin/uwsgi --listen $(cat /proc/sys/net/core/somaxconn) --daemonize -- /srv/app/app.ini'
