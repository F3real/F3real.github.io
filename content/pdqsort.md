Title: Pdqsort
Date: 2019-5-22 10:01
Modified: 2019-5-22 10:01
Category: misc
Tags: sorting, algorithm
Slug: pdqsort
Authors: F3real
Summary: Quick intro to pdqsort



Pdqsort (Pattern-defeating quicksort) is another interesting sorting algorithm, originally it was made as a replacement for C++ `std::sort`. It is also a relatively new algorithm, made around 2015. Pdqsort is implemented in boost and it is implemented in rust stdlib (`sort_unstable`).

~~~text
Best:     O(n)
Average:  O(n logn)
Worst:    O(n logn)
Memory    O(n)
~~~

Like timsort, pdqsort is also a hybrid algorithm. It uses insertion sort, heap sort and quicksort. Since it uses quicksort it is also unstable.

Let's take high-level overview of rust implementation:


The main function of the algorithm is `recurse`. It calculates pivot using the median of medians (or simple median of three if slice length is bellow 50). After that `recurse` splits/partitions slice in two, left side with elements smaller than pivot and right side bigger then pivot. 

The function `recurse` is then recursively called on smaller of the two parts to reduce recursion depth while it keeps looping on the bigger part.

While all of this is happening, `recurse` also tracks the state of partitions:

* if they were balanced
* if they were likely sorted
* if slice was already partitioned
* recursion depth

If the partition wasn't balanced, the algorithm will attempt to break patterns by randomly swapping 4 elements. This is checked based on the index of the element in the middle (last element in the left partition) and the total length of the slice.

~~~rust
cmp::min(mid, len - mid) >= len / 8;
~~~

If the partition is likely sorted, the algorithm will try to do partial insertion sort (max 5 pairs swapped) to speed up the sorting of partition. This is decided based on a number of swaps when choosing the pivot element.

In case recursion depth starts growing, pdqsort switches to heapsort to ensure `O(n log n)` worst-case. Max recursion depth is calculated based on array length.

Also, similar to timsort, if the length of slice/partition is short algorithm will switch to insertion sort (len<=20).

Another optimization pdqsort does is detecting if there are many equal elements, in that case, it performs special partitioning. This happens if we select pivot equal to the previous one. In this case, all elements equal to pivot will be put in the left partition.

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

If the algorithm seems interesting and you want to dive in more details, I suggest you to also look at the following resources:

[Rust stdlib implementation](https://github.com/rust-lang/rust/blob/master/src/libcore/slice/sort.rs)

[Original C++ implementation made by Orson](https://github.com/orlp/pdqsort)

[Draft algorithm paper](https://drive.google.com/file/d/0B1-vl-dPgKm_T0Fxeno1a0lGT0E/view)
