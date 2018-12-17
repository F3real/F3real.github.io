#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = 'F3real'
SITENAME = 'EnSec blog'
SITEURL = 'https://f3real.github.io'

PATH = 'content'

TIMEZONE = 'Europe/Belgrade'

DEFAULT_LANG = 'en'
LOCALE = ('usa')

STATIC_PATHS = ['images', 'extra/robots.txt',]
EXTRA_PATH_METADATA = {
    'extra/robots.txt': {'path': 'robots.txt'},
}

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Blogroll
LINKS = ()

# Social widget
SOCIAL = (('Github', 'https://github.com/F3real'),
          ('Linkedin', 'https://www.linkedin.com/in/stefan-ili%C4%87-61a004111'),)

DEFAULT_PAGINATION = 6

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True

MARKDOWN = {
    'extension_configs': {
        'markdown.extensions.codehilite': {'css_class': 'highlight'},
        'markdown.extensions.extra': {},
        'markdown.extensions.meta': {},
        'markdown.extensions.meta': {},
        'markdown.extensions.toc': {},
    },
    'output_format': 'html5',
}

# Theme
THEME = "pelican-twitchy"

# Theme settings
PYGMENTS_STYLE = 'monokai'
SITESUBTITLE = "Security && programming randomness"
BOOTSTRAP_THEME = "sandstone"
DISQUS_SITENAME = "https-f3real-github-io"
DISQUS_LOAD_LATER = True