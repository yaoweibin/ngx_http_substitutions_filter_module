# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the "substitution" command with default types
--- config
    location / {
        subs_filter 'tom' 'yaoweibin' ir;
        root html;
    }
--- user_files
>>> a.html
tom and jerry
--- request
    GET /a.html
--- response_body_unlike: ^(.*)tom(.*)$

=== TEST 2: the "substitution" command with css types
--- config
    location / {
        subs_filter_types text/css;
        subs_filter 'tom' 'yaoweibin' ir;
        root html;
    }
--- user_files
>>> a.xml
tom and jerry
--- request
    GET /a.xml
--- response_body_like: ^(.*)tom(.*)$

=== TEST 3: the "substitution" command with xml types
--- config
    types {
        text/html html;
        text/xml xml;
        text/css  css;
    }
    location / {
        subs_filter_types text/xml;
        subs_filter 'tom' 'yaoweibin' ir;
        root html;
    }
--- user_files
>>> a.xml
tom and jerry
--- request
    GET /a.xml
--- response_body_unlike: ^(.*)tom(.*)$
