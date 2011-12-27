#
#===============================================================================
#
#         FILE:  sample.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
$ENV{TEST_NGINX_BACKENDS_PORT} ||= "blog.163.com:80";
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "substitution" command

--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config
    
    location / {
        subs_filter '163\.com' 'yaoweibin' ir;
        proxy_set_header Host 'blog.163.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_unlike: ^(.*)163\.com(.*)$
