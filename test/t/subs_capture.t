
# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
$ENV{TEST_NGINX_BACKENDS_PORT} ||= "blog.163.com:80";
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "regex with captures substitution" command
--- http_config

    upstream backends {
        server $TEST_NGINX_BACKENDS_PORT;
    }

--- config

    location / {      
        subs_filter '163.(com)' 'yaoweibin.$1' ir;
        proxy_set_header Host 'blog.163.com';
        proxy_pass http://backends;
    }
--- request
    GET /
--- response_body_unlike: ^(.*)163.com(.*)$
