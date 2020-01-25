Title: GoatCounter
Date: 2020-1-17 10:02
Modified: 2020-1-17 10:02
Category: misc
Tags: js, statistics
Slug: goatcounter
Authors: F3real
Summary: Adding statistics to the blog

Originally, I have excluded all 3rd party scripts from the blog. This made only mean tracking user visits click data in search engine results (and those are tracked anyway by Google, Yandex etc. so why not have access to the data as well) but this approach was a bit nuclear. 

Basically all data from visitors coming to the blog using direct links or information regarding users navigation from page to page was missing.

And this data is definitely interesting to the owners but still, there is no need to help google track users even more (google analytics). So what are the alternatives?

There are some, quite good, open source alternatives actually ([matomo](https://matomo.org/), [fathom](https://usefathom.com/)) but I found their pricing options lacking. This is especially true for hobby sites like this blog where the expected visitor number per month is not more than a few thousand, so why pay for 100k visitors a month. There is an option for self-hosting but it's not always the most practical solution.

So while looking for privacy-friendly, open-source, web statistics I've stumbled upon [GoatCounter](https://www.goatcounter.com/). 
It's quite a new project but for now, it looks quite promising. By default it tracks:

* path
* title
* domain
* referrer

You own your data and users are not tracked with unique identifiers making it GDPR compliant. And key thing is, it provides a free tier for personal usage (you can set monthly donation amount if you wish).

Once you register, you just have to add small `js` snippet to all of your pages and setup is done.

~~~js
<script>
	(function() {
		window.counter = 'https://<username>.goatcounter.com/count'

		var script = document.createElement('script');
		script.async = 1;
		script.src = '//gc.zgo.at/count.js';
		var ins = document.getElementsByTagName('script')[0];
		ins.parentNode.insertBefore(script, ins)
	})();
</script>
~~~

So from now on, this blog is using GoatCounter, let's see how it goes.
