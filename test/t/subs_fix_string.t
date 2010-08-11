
# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "fix string substitution" command
--- config
    location / {      
        subs_filter '163.com' 'yaoweibin';
        proxy_pass http://blog.163.com/;
    }
--- request
    GET /
--- response_body_unlike: ^(.*)163\.com(.*)$
