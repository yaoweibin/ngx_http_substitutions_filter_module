# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "substitution" command with build-in variable matching
--- config
    location / {
        subs_filter_types text/plain;
        subs_filter http://$host https://$host;
    }
--- user_files
>>> foo.txt
http://localhost
--- request
    GET /foo.txt
--- response_body_like: ^https://localhost$

=== TEST 2: the "substitution" command with custom variable matching
--- config
    location / {
        set $foo foo;
        subs_filter_types text/plain;
        subs_filter $foo bar;
    }
--- user_files
>>> foo.txt
barfoobar
--- request
    GET /foo.txt
--- response_body_like: ^(bar){3}$

=== TEST 3: the "substitution" command with insensitive matching
--- config
    location / {
        subs_filter_types text/plain;
        subs_filter foobar hello;
        subs_filter foobar world i;
    }
--- user_files
>>> foo.txt
FoObAr
--- request
    GET /foo.txt
--- response_body_like: ^world$

