#!/bin/sh

# 
# Test::LongString Module of perl is needed
# You can install it with `cpan install Test::LongString`
#

#
# Basic Usage.
#  TEST_NGINX_SBIN_PATH=/path/to/nginx/sbin \
#  ./test.sh
#

#
# Custom Backend Server
#  TEST_NGINX_SBIN_PATH=/path/to/nginx/sbin \
#  TEST_NGINX_BACKENDS_PORT=ip:port \
#  ./test.sh

TEST_NGINX_SBIN_PATH=${TEST_NGINX_SBIN_PATH:=/path/to/nginx/sbin}
PATH=$TEST_NGINX_SBIN_PATH:$PATH prove -r t

#
# The command of @yaoweibin
#
# nginx sbin path
# TEST_NGINX_SBIN_PATH=/home/yaoweibin/nginx/sbin

# 
# basic test with backend www.taobao.com:80
#
# PATH=$TEST_NGINX_SBIN_PATH:$PATH prove -r t

#
# custom test with custom backend
#
# TEST_NGINX_BACKENDS_PORT=127.0.0.1:1234 \
# PATH=$TEST_NGINX_SBIN_PATH:$PATH prove -r t


