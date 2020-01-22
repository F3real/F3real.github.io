Title: Opensubtitles addon
Date: 2020-1-5 10:01
Modified: 2020-1-5 10:01
Category: misc
Tags: javascript, browser 
Slug: opensubtitles_addon
Authors: F3real
Summary: Exploring opensubtitles browser addon

[Opensubtitles](https://www.opensubtitles.org/) is a site I periodically use when trying to find subtitles for movies and it usually works without any issues. But this time along with the requested subtitles site also tried to serve me with an addon.

Definitely sketchy behavior so I decided to see what exactly does it do.

The addon is `sub_search-1.0.0-an+fx.xpi` and like all `xpi` files it is basically just a zip. The structure of `xpi` files is quite similar to `apk` files used in android (or Java `jar` files), both have `META-INF` folder with signatures and `manifest` file with listed permissions and general information.

So let's look at `manifest.json` first:

~~~json
  "background": { /*  Events are browser triggers, such as navigating to a new page, removing a bookmark, or closing a tab. Extensions monitor these events in their background script, then react with specified instructions. */
    "persistent": false,
    "scripts": [ "js/background.js" ]
  },
  "chrome_settings_overrides": { /*override certain browser settings */
    "search_provider": { /*enables you to add a new search engine*/
      "encoding": "UTF-8",
      "favicon_url": "https://search.becovi.com/images/becovi-favicon.ico",
      "is_default": true, /* set newly added search provider as default */
      "keyword": "Sub Search",
      "name": "Sub Search",
      "search_url": "https://search.becovi.com/serp.php?q={searchTerms}&i=OWY6G4MSAC&atr=001"
    }
  }
  ...
  ...
    "permissions": [ "https://www.opensubtitles.org/","https://www.opensubtitles.com/"],
  /* Content scripts are files that run in the context of web pages. By using the standard Document Object Model (DOM), they are able to read details of the web pages the browser visits, make changes to them and pass information to their parent extension. */
  "content_scripts": [
    {
      "matches": [ /*  Use declarative injection for content scripts that should be automatically run on specified pages.  */
        "https://www.opensubtitles.org/*","https://www.opensubtitles.com/*"
      ],
      "js": [
        "js/headerinject.js"
      ]
    }
  ]
~~~

Apparently, only semi-bad thing addon does is hijacking default search engine. I say semi-bad since it is clearly written on [Chrome addon page](https://chrome.google.com/webstore/detail/opensub-search/dkpeabmcccfccdlaeejhkapiofpjolaf). For some strange reason, if you visit the site with Firefox, as in my case, it will try to make you download the addon directly.

The permissions of the addon are reasonable, it requests the right to modify and access only `opensubtitles` tabs.

I actually was expecting at least some sort of malicious activity since they decided for this suspicious delivery method.

For the main functionality of addon we have to take a look into `background.js` and `headerinject.js`. 
The `background.js` is tasked with, when addon is installed, to try and inject `headerinject.js` in all `opensubtitles` tabs.

~~~js
function sendContentScripts() {
    var injectInTab = function (tab) {
        /* Injects JavaScript code into a page. */
        chrome.tabs.executeScript(tab.id, {"file": "headerinject.js"}, function() { 
            var err = chrome.runtime.lastError;
            if (err) {
                return;
            }
        });
    };
    chrome.windows.getAll({
        populate: true
    }, function (windows) {
        var w = windows.length, currentWindow;
        for (var i = 0; i < w; i++) { /* Go over all windows. */
            currentWindow = windows[i];
            var t = currentWindow.tabs.length, currentTab;
            for (var j = 0; j < t; j++) { /* Go over all tabs in a window. */
                currentTab = currentWindow.tabs[j];
                // Skip chrome:// pages
                if (currentTab.url && !currentTab.url.match(/(chrome):\/\//gi)){
                    injectInTab(currentTab);
                }
            }
        }
    });
}
/* Listen to the runtime.onInstalled event to initialize an extension on installation. Use this event to set a state or for one-time initialization, such as a context menu.
Fired when the extension is first installed, when the extension is updated to a new version, and when Chrome is updated to a new version. */
chrome.runtime.onInstalled.addListener(function(details){
    sendContentScripts();
});
~~~

And `headerinject.js` is tasked to ensure that user is identified as premium user thus removing all advertisement. Whole `js` code is given here:

~~~js
var meta = document.createElement('meta');
meta.name = "accesslevel";
meta.content = "extpremium";
meta.id = "extinstalled";
document.getElementsByTagName('head')[0].appendChild(meta);
console.log('Pro enabled');
~~~

Basically, check is so simple it is easily bypassed by simply injecting the same `js` object on our own.

As a reminder, if you want to test and play with the addon, it is quite easy to load custom addon both in Firefox and Chrome.

In Firefox you have to navigate to `about:debugging` then go  `This Firefox -> Load Temporary Add-on...` and select manifest in unpacked addon folder. (funny thing is current addon they have is not even working in current Firefox 72)

In Chrome you have to navigate to `chrome://extensions/` enable `Developer mode` and then use `Load unpacked` to select addon folder.

And as an endnote, injecting `headerinject.js` does actually hide some advertisement but a combination of `NoScript` and `AddBlockPlus` is still far superior.