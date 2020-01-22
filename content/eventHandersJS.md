Title: Using MutationObserver and MediaQuery 
Date: 2019-3-6 10:01
Modified: 2019-3-6 10:01
Category: misc
Tags: js, MutationObserver, MediaQuery
Slug: mutationobserver_mediaquery
Authors: F3real
Summary: How to use MutationObserver and MediaQuery to dynamically handle changes on page


While trying to make the blog more accessible for users especially for those who use the keyboard I hit an interesting problem. How to trigger JS code on CSS changes?

Usually, I only used events to react to mouse clicks. For example, if we wanted to create behavior similar to boostrap collapse we could add this JS code:

~~~js
    element.addEventListener('click', (ev) => {
        //current target not necessarily element on which event occurred
        const elm = ev.currentTarget;    
        ev.preventDefault();
        const selector = elm.getAttribute('href').replace('#','');
        elm.classList.toggle('collapsed');
        document.getElementById(selector).classList.toggle('show');
    }, false);
~~~

But what happens if we want to react, for example, on class being added to an element? The solution is to use `MutationObserver`. We can set it up to react on attribute change (or only specific attribute), adding/removing child nodes or even setting it to observe the whole subtree. It is also reasonably efficient, the callback will be triggered only after DOM has finished changing.

Example of creating `MutationObserver` for all attributes on the element:

~~~js
    var mutationCallback = function(mutationsList, observer) {
        for(var mutation of mutationsList) {
            if (mutation.type == 'attributes') {
                console.log('Attribute changed');
            }
        }
    };
    var observer = new MutationObserver(mutationCallback);
    observer.observe(element, { attributes: true});
~~~

Also, even with `MutationObserver` we can't write code that will trigger on CSS changes themselves (unless there is class being added/removed). Changes in CSSOM are not detectable with `MutationObserver`. CSS is usually fixed but `@media` queries can trigger change on width/height/orientation changes. The solution to this problem is to create an event handler for those changes using `onchange` property of the `MediaQueryList` interface.

For example to react on screen width changes, we can use:

~~~js
    const mediaQuery = window.matchMedia('(min-width:768px)');
    mediaQuery.onchange = e => {
        if (e.matches) {
            console.log('Condition is true')
        } else {
            console.log('Condition is false')
        }
    }
~~~

So, in summary, these are some of the ways we can add handlers for different changes on our page.
