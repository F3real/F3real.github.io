Title: Pdqsort
Date: 2019-5-22 10:01
Modified: 2019-5-22 10:01
Category: misc
Tags: sorting, algorithm
Slug: pdqsort
Authors: F3real
Summary: Quick intro to pdqsort



Pdqsort (Pattern-defeating quicksort) is another interesting sorting algorithm, originally it was made as replacement for C++ `std::sort`. It is also relatively new algorithm, made around 2015. Pdqsort is implemented in boost and it is implemented in rust stdlib (`sort_unstable`).

~~~text
Best:     O(n)
Average:  O(n logn)
Worst:    O(n logn)
Memory    O(n)
~~~

Like timsort pdqsort is also hybrid algorithm. It uses insertion sort, heap sort and quicksort. Since it uses quicksort it is also unstable.

Let's take high level overview of rust implementation:


Main function of algorithm is `recurse`. It calculates pivot using median of medians (or simple median of three if slice length is bellow 50). After that `recurse` splits/partitions slice in two, left side with elements smaller then pivot and right side bigger then pivot. 

Function `recurse` is then recursively called on smaller of the two parts to reduce recursion depth while it keeps looping on bigger part.

While all of this is happening, `recurse` also tracks state of partitions:

* if they were balanced
* if they were likely sorted
* if slice was already partitioned
* recursion depth

If partition wasn't balanced, algorithm will attempt to break patterns by randomly swapping 4 elements. This is checked based on index of element in the middle (last element in left partition) and total length of slice.

~~~rust
cmp::min(mid, len - mid) >= len / 8;
~~~

If partition is likely sorted algorithm will try to do partial insertion sort (max 5 pairs swapped) to speed up sorting of partition. This is decided based on number of swaps when choosing pivot element.

In case recursion depth starts growing, pdqsort switches to heapsort to ensure `O(n log n)` worst-case. Max recursion depth is calculated based on array length.

Also, similar to timsort, if length of slice/partition is short algorithm will switch to insertion sort (len<=20).

Another optimization pdqsort does is detecting if there are many equal elements, in that case it perform special partitioning. This happens if we select pivot equal to previous one. In this case all element equal to pivot will be put in left partition.

Partitioning itself is done in blocks, in branchless manner, using work from [BlockQuicksort: Avoiding Branch Mispredictions in Quicksort](http://drops.dagstuhl.de/opus/volltexte/2016/6389/pdf/LIPIcs-ESA-2016-38.pdf) as another optimization.

We avoid branch misses by casting boolean to int (SETcc instructions). This gives better performance then unpredictable branches (like in sorting case).

Example of branchless comparison:
~~~rust
for i in 0..block_l {
    unsafe {
        // Set index of element that should be swapped.
        *end_l = i as u8;
        /* Increment pointer to end element(end_l) conditionally.
           In case it's not incremented in next iteration we will overwrite index we set in previous line.
        */
        end_l = end_l.offset(!is_less(&*elem, pivot) as isize);
        // Increment pointer to next element in slice.
        elem = elem.offset(1);
    }
}
~~~

If algorithm seems interesting and you want to dive in more details, I suggest you to also look at following resources:

[Rust stdlib implementation](https://github.com/rust-lang/rust/blob/master/src/libcore/slice/sort.rs)

[Original C++ implementation made by Orson](https://github.com/orlp/pdqsort)

[Draft algorithm paper](https://drive.google.com/file/d/0B1-vl-dPgKm_T0Fxeno1a0lGT0E/view)
