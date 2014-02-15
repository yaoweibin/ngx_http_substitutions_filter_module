
# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
$ENV{TEST_NGINX_BACKENDS_PORT} ||= "www.taobao.com:80";
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "regex substitution" command
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config

    location / {
        subs_filter 'taobao.com' 'yaoweibin' ir;
        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_unlike: ^(.*)taobao.com(.*)$

=== TEST 2: the "subs_filter_bypass" directive, one variable
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config
    set $bypass "1";
    location / {
        subs_filter 'taobao.com' 'yaoweibin' ir;
        subs_filter_bypass $bypass;
        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_like: ^(.*)taobao.com(.*)$

=== TEST 3: the "subs_filter_bypass" directive, two variables
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config
    set $foo "0";
    set $bypass "1";
    location / {
        subs_filter 'taobao.com' 'yaoweibin' ir;
        subs_filter_bypass $foo $bypass;
        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_like: ^(.*)taobao.com(.*)$

=== TEST 4: the "subs_filter_bypass" directive, raw string
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config
    location / {
        subs_filter 'taobao.com' 'yaoweibin' ir;
        subs_filter_bypass "1";
        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_like: ^(.*)taobao.com(.*)$

=== TEST 5: the "subs_filter_bypass" directive, raw string
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config
    location / {
        subs_filter 'taobao.com' 'yaoweibin' ir;
        subs_filter_bypass "0";
        proxy_set_header Host 'www.taobao.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_unlike: ^(.*)taobao.com(.*)$
