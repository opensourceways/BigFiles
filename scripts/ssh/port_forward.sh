#!/bin/bash
sshpass -p '123456' ssh -L 23231:gitee.com:22 -o ServerAliveInterval=20 -o StrictHostKeyChecking=no -gNf localhost