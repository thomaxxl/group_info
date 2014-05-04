linux
=====

This repository holds code to help exploiting CVE-2014-2851: Linux group_info refcounter overflow use afer free.

- ping_of.c calls ping_init_sock() argv[1] times. Doing this in python would make things too slow. 

- ping.py contains a client and a server function. 

The client function does the following:
- call ping_init_sock() to increase the refcounter
- call faccessat(), this syscall increments, then decrements the refcounter. If the refcounter became zero because of ping_init_sock, the group_info struct will be freed.
- requests the server to open 1000 file descriptors. On my system (32 bit ubuntu), the file structs are allocated in the same memcache as the group_info struct.(kmalloc-192)
- call getgroups(), if group_info has been freed and reused, this counter has been overwritten by another value. This way, we can see if group_info has been freed. 
we wait 15 seconds between faccessat and getgroups because the group_info struct may not have been overwritten yet.
 

The server opens a number of fds on request in order to use the freed memory. This should be called in a separate session because the credentials are shared between parent and child processes.

first, execute ping_of.c . This will increment the refcounter close to zero (e.g. -20).
next, in a different session,  execute "ping.py -s"
finally, in the first session, execute "ping.py -c"

[ Session 1 ]
```
t@tpollet-ubuntu-vm:/tmp$ ./ping_of -20
...
<output omitted>
...
t@tpollet-ubuntu-vm:/tmp$ ./ping.py -c
Starting client

numgroups: 8
numgroups: -1055523072
>
```
[Session 2]
```
t@tpollet-ubuntu-vm:/tmp$ ./ping.py -s
Starting Server
opening 1000 fds
opening 1000 fds
```
                        
The numgroups output by ping.py is returned by the getgroups system call. This comes from the group_info struct being overwritten by a file struct.
The group_info struct looks like this: 

```
include/linux/cred.h
32 struct group_info {
33         atomic_t        usage;            // refcounter
34         int             ngroups;          // return value of getgroups
35         int             nblocks;
36         kgid_t          small_block[NGROUPS_SMALL];
37         kgid_t          *blocks[0];
38 };
```
The file struct looks like this:
```
include/linux/fs.h
775 struct file {
776         union {
777                 struct llist_node       fu_llist;
778                 struct rcu_head         fu_rcuhead;
779         } f_u;
780         struct path             f_path;
781 #define f_dentry        f_path.dentry
782         struct inode            *f_inode;       /* cached value */
783         const struct file_operations    *f_op;
784 
....

include/linux/llist.h
65 struct llist_node {
66         struct llist_node *next;
67 };
```
So, after the free, getgroups() looks up the value on the location where ngroups was before it was freed. This location now holds fu_rcuhead .
We are still able to increment fu_llist by calling ping_init_sock().