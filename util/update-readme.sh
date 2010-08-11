#!/bin/bash

perl util/wiki2pod.pl README.wiki > /tmp/a.pod && pod2text /tmp/a.pod > README

perl util/wiki2pod.pl README.wiki > /tmp/a.pod && pod2html /tmp/a.pod > README.html

perl util/wiki2google_code_homepage.pl README.wiki > README.google_code_home_page.wiki
