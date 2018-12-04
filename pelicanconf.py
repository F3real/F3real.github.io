#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = 'F3real'
SITENAME = 'EnSec blog'
SITEURL = ''

PATH = 'content'

TIMEZONE = 'Europe/Belgrade'

DEFAULT_LANG = 'en'

STATIC_PATHS = ['images']

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Blogroll
LINKS = ()

# Social widget
SOCIAL = (('Github', 'https://github.com/F3real'),)

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True

# Theme
THEME = "pelican-twitchy"
SITESUBTITLE = "Security && programming randomness"
BOOTSTRAP_THEME = "sandstone"
DISQUS_SITENAME = "https-f3real-github-io"
DISQUS_LOAD_LATER = True

PYGMENTS_STYLE = 'paraiso-light'