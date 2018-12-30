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

STATIC_PATHS = ['images', 'extra']
EXTRA_PATH_METADATA = {
    'extra/robots.txt': {'path': 'robots.txt'},
    'extra/google26d6dbcb9aa6bb14.html': {'path': 'google26d6dbcb9aa6bb14.html'},
    'extra/yandex_7992e0c81815ff69.html': {'path': 'yandex_7992e0c81815ff69.html'},
    'extra/BingSiteAuth.xml': {'path': 'BingSiteAuth.xml'},
    'extra/favicon.ico': {'path': 'favicon.ico'},
}
# Directories excluded from pelican processing
PAGE_EXCLUDES = ['extra']
ARTICLE_EXCLUDES = ['extra']

PLUGINS = [
    'extended_sitemap'
]

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

# Sets pagination for different types
PAGINATED_TEMPLATES = {'index': 6, 'tag': 12, 'category': 12, 'author': None}
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