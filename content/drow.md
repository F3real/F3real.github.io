Title: Drow ELF patcher
Date: 2020-12-5 10:02
Modified: 2020-12-5  10:02
Category: misc
Tags: elf, c, linux
Slug: drow
Authors: F3real
Summary: Utility for patching ELF files post-build

In the [drow](https://github.com/zznop/drow) readme there is a short explanation on how the tool works but here I will try to provide a bit of background information regarding ELF segments and sections and how they are aligned in memory. 

## ELF segments and sections

The ELF file structures are defined in [elf.h](http://man7.org/linux/man-pages/man5/elf.5.html) header. 

To access the ELF header we can `mmap` executable in and assign it to the `Elf64_Ehdr` structure.

Something like:

~~~c
uint8_t *data = (void *)mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
~~~

An executable `program header table` is an array of structures, each describing a segment or other information the system needs to prepare the program for execution. The program is mapped from disk to virtual memory according to defined segments. Each entry is `Elf64_Phdr` structure. It is important to note that there are different types (`p_type`) of segments and that only `PT_LOAD` segments get loaded in memory.
Program headers are meaningful only for executable and shared object files.

We can view all segments of ELF using:

~~~text
readelf -l <target>
~~~


A file's `section header table` lets one locate all the file's sections. The section header table is an array of `Elf64_Shdr` structures. Sections contain important data for linking and relocation. Each segment contains 0 or more sections.

We can view all sections of ELF using:

~~~text
readelf -S <target>
~~~

Both tables can be accessed trough ELF header:

~~~c
Elf64_Phdr *phdr;
Elf64_Shdr *shtable;
phdr = (Elf64_Phdr *)((uintptr_t)data + ehdr->e_phoff);
shtable = (Elf64_Shdr *)((uintptr_t)data + ehdr->e_shoff);
~~~

A good illustration of the relation between sections (on the left) and segments (on the right) is given in the image bellow [source](https://intezer.com/blog/research/executable-linkable-format-101-part1-sections-segments/).

![Sections and Segments]({static}/images/2020_12_5_SegmentsAndSections.png){: .img-fluid .centerimage}

Sections are grouped by attributes into segments in order to make the loading process of the executable more efficient, instead of loading each individual section into memory. 

For segments following must hold:

~~~text
({Virt,Phys}Addr - Offset) % PageSize == 0
~~~

To align value to for example 8 bytes we need to use an alignment mask of 7 (8 - 1). The `drow` is using this procedure to align the new section size to page size.

~~~text
value & ~(alignment - 1)
~~~

To successfully modify the size of one section, we need to increase the offset of all the following sections by the same amount.  The same holds true for segment entries in `program header table` as well as offsets of tables themselves in the ELF header if they are after the modified section.

And that's about it. There are few more tricks like writing stager for payload for those interested but I won't go into details how they work here. In general it's a pretty straightforward working tool that provides a nice way to get more familiar with ELF structure.