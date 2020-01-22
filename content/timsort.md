Title: Timsort
Date: 2019-5-18 10:01
Modified: 2019-5-18 10:01
Category: misc
Tags: sorting, algorithm
Slug: timsort
Authors: F3real
Summary: Quick intro to timsort



Timsort is the default sorting algorithm used in Python, Java (for objects) and variation of it is used as default Rust sorting algorithm. All of this makes it really interesting algorithm to understand, so let's take a look:

Timsort is a stable, hybrid sorting algorithm combining merge sort and insertion sort. Complexity:

~~~text
Best:     O(n)
Average:  O(n logn)
Worst:    O(n logn)
Memory    O(n)
~~~

The algorithm starts by finding sequences of sorted elements `runs`. If a run is descending it is simply reversed in place. 

The minimum size of each run `minrun` is calculated beforehand, based on the length of the array we are sorting. This value can be in the range from 32 up to and including 64. Size of `minrun` should such that length of the array, divided by `minrun`, is equal to, or slightly less than, a power of two (for efficient merging).

Although it sounds complicated algorithm is actually quite simple, we will shift right the number representing the length of array until only last 6, most significant, bits are remaining and add 1 if any of bits shifted out was 1.

~~~rust
pub fn get_minrun(len: usize) -> usize {
    let mut r = 0;
    let mut new_len = len;
    while new_len >= MIN_RUN {
        r |= new_len & 1;
        new_len >>= 1;
    }
    new_len + r
}
~~~

While we are creating runs, if any of them has a length less then `minrun` it will be expanded. This is done by adding elements following it until we reach the `minrun` size. Since this run will not be sorted, before it is added to other runs, insertion sort is applied to it. Insertion sort is also used if given array has a length smaller then 64, turning timsort in insertion sort in this case.

Runs are combined together using merge sort while keeping following invariants:
~~~text
|run i| > |run i + 1|
|run i| > |run i + 1| + |run i + 2|
~~~

If they are not satisfied we merge adjacent runs, and we keep doing it until they hold.

Timsort also implements galloping optimization for merge sort, which I won't go into.

If the algorithm seems interesting and you want to dive in more details, I suggest you to also look at the following resources:

[Rust stdlib implementation of modified timsort](https://github.com/rust-lang/rust/blob/master/src/liballoc/slice.rs)

[Original python post](https://svn.python.org/projects/python/trunk/Objects/listsort.txt)