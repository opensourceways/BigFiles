#!/bin/bash
#/usr/sbin/sshd &
systemctl restart sshd &
/port_forward.sh &
wait