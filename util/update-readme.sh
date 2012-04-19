#!/bin/sh

perl util/wiki2pod.pl doc/README.wiki > /tmp/a.pod && pod2text /tmp/a.pod > README

perl util/wiki2pod.pl doc/README.wiki > /tmp/a.pod && pod2html /tmp/a.pod > doc/README.html

perl util/wiki2google_code_homepage.pl doc/README.wiki > doc/README.google_code_home_page.wiki
