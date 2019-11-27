[syscall defination](https://github.com/torvalds/linux/tree/v4.3/arch/x86/entry/syscalls)

### x86_64

%rax | name | entry point | implementation
--- | --- | --- | ---
0 | read | sys_read | fs/read_write.c
1 | write | sys_write | fs/read_write.c
2 | open | sys_open | fs/open.c
3 | close | sys_close | fs/open.c
4 | stat | sys_newstat | fs/stat.c
5 | fstat | sys_newfstat | fs/stat.c
6 | lstat | sys_newlstat | fs/stat.c
7 | poll | sys_poll | fs/select.c
8 | lseek | sys_lseek | fs/read_write.c
9 | mmap | sys_mmap | arch/x86/kernel/sys_x86_64.c
10 | mprotect | sys_mprotect | mm/mprotect.c
11 | munmap | sys_munmap | mm/mmap.c
12 | brk | sys_brk | mm/mmap.c
13 | rt_sigaction | sys_rt_sigaction | kernel/signal.c
14 | rt_sigprocmask | sys_rt_sigprocmask | kernel/signal.c
15 | rt_sigreturn | stub_rt_sigreturn | arch/x86/kernel/signal.c
16 | ioctl | sys_ioctl | fs/ioctl.c
17 | pread64 | sys_pread64 | fs/read_write.c
18 | pwrite64 | sys_pwrite64 | fs/read_write.c
19 | readv | sys_readv | fs/read_write.c
20 | writev | sys_writev | fs/read_write.c
21 | access | sys_access | fs/open.c
22 | pipe | sys_pipe | fs/pipe.c
23 | select | sys_select | fs/select.c
24 | sched_yield | sys_sched_yield | kernel/sched/core.c
25 | mremap | sys_mremap | mm/mmap.c
26 | msync | sys_msync | mm/msync.c
27 | mincore | sys_mincore | mm/mincore.c
28 | madvise | sys_madvise | mm/madvise.c
29 | shmget | sys_shmget | ipc/shm.c
30 | shmat | sys_shmat | ipc/shm.c
31 | shmctl | sys_shmctl | ipc/shm.c
32 | dup | sys_dup | fs/file.c
33 | dup2 | sys_dup2 | fs/file.c
34 | pause | sys_pause | kernel/signal.c
35 | nanosleep | sys_nanosleep | kernel/hrtimer.c
36 | getitimer | sys_getitimer | kernel/itimer.c
37 | alarm | sys_alarm | kernel/timer.c
38 | setitimer | sys_setitimer | kernel/itimer.c
39 | getpid | sys_getpid | kernel/sys.c
40 | sendfile | sys_sendfile64 | fs/read_write.c
41 | socket | sys_socket | net/socket.c
42 | connect | sys_connect | net/socket.c
43 | accept | sys_accept | net/socket.c
44 | sendto | sys_sendto | net/socket.c
45 | recvfrom | sys_recvfrom | net/socket.c
46 | sendmsg | sys_sendmsg | net/socket.c
47 | recvmsg | sys_recvmsg | net/socket.c
48 | shutdown | sys_shutdown | net/socket.c
49 | bind | sys_bind | net/socket.c
50 | listen | sys_listen | net/socket.c
51 | getsockname | sys_getsockname | net/socket.c
52 | getpeername | sys_getpeername | net/socket.c
53 | socketpair | sys_socketpair | net/socket.c
54 | setsockopt | sys_setsockopt | net/socket.c
55 | getsockopt | sys_getsockopt | net/socket.c
56 | clone | stub_clone | kernel/fork.c
57 | fork | stub_fork | kernel/fork.c
58 | vfork | stub_vfork | kernel/fork.c
59 | execve | stub_execve | fs/exec.c
60 | exit | sys_exit | kernel/exit.c
61 | wait4 | sys_wait4 | kernel/exit.c
62 | kill | sys_kill | kernel/signal.c
63 | uname | sys_newuname | kernel/sys.c
64 | semget | sys_semget | ipc/sem.c
65 | semop | sys_semop | ipc/sem.c
66 | semctl | sys_semctl | ipc/sem.c
67 | shmdt | sys_shmdt | ipc/shm.c
68 | msgget | sys_msgget | ipc/msg.c
69 | msgsnd | sys_msgsnd | ipc/msg.c
70 | msgrcv | sys_msgrcv | ipc/msg.c
71 | msgctl | sys_msgctl | ipc/msg.c
72 | fcntl | sys_fcntl | fs/fcntl.c
73 | flock | sys_flock | fs/locks.c
74 | fsync | sys_fsync | fs/sync.c
75 | fdatasync | sys_fdatasync | fs/sync.c
76 | truncate | sys_truncate | fs/open.c
77 | ftruncate | sys_ftruncate | fs/open.c
78 | getdents | sys_getdents | fs/readdir.c
79 | getcwd | sys_getcwd | fs/dcache.c
80 | chdir | sys_chdir | fs/open.c
81 | fchdir | sys_fchdir | fs/open.c
82 | rename | sys_rename | fs/namei.c
83 | mkdir | sys_mkdir | fs/namei.c
84 | rmdir | sys_rmdir | fs/namei.c
85 | creat | sys_creat | fs/open.c
86 | link | sys_link | fs/namei.c
87 | unlink | sys_unlink | fs/namei.c
88 | symlink | sys_symlink | fs/namei.c
89 | readlink | sys_readlink | fs/stat.c
90 | chmod | sys_chmod | fs/open.c
91 | fchmod | sys_fchmod | fs/open.c
92 | chown | sys_chown | fs/open.c
93 | fchown | sys_fchown | fs/open.c
94 | lchown | sys_lchown | fs/open.c
95 | umask | sys_umask | kernel/sys.c
96 | gettimeofday | sys_gettimeofday | kernel/time.c
97 | getrlimit | sys_getrlimit | kernel/sys.c
98 | getrusage | sys_getrusage | kernel/sys.c
99 | sysinfo | sys_sysinfo | kernel/sys.c
100 | times | sys_times | kernel/sys.c
101 | ptrace | sys_ptrace | kernel/ptrace.c
102 | getuid | sys_getuid | kernel/sys.c
103 | syslog | sys_syslog | kernel/printk/printk.c
104 | getgid | sys_getgid | kernel/sys.c
105 | setuid | sys_setuid | kernel/sys.c
106 | setgid | sys_setgid | kernel/sys.c
107 | geteuid | sys_geteuid | kernel/sys.c
108 | getegid | sys_getegid | kernel/sys.c
109 | setpgid | sys_setpgid | kernel/sys.c
110 | getppid | sys_getppid | kernel/sys.c
111 | getpgrp | sys_getpgrp | kernel/sys.c
112 | setsid | sys_setsid | kernel/sys.c
113 | setreuid | sys_setreuid | kernel/sys.c
114 | setregid | sys_setregid | kernel/sys.c
115 | getgroups | sys_getgroups | kernel/groups.c
116 | setgroups | sys_setgroups | kernel/groups.c
117 | setresuid | sys_setresuid | kernel/sys.c
118 | getresuid | sys_getresuid | kernel/sys.c
119 | setresgid | sys_setresgid | kernel/sys.c
120 | getresgid | sys_getresgid | kernel/sys.c
121 | getpgid | sys_getpgid | kernel/sys.c
122 | setfsuid | sys_setfsuid | kernel/sys.c
123 | setfsgid | sys_setfsgid | kernel/sys.c
124 | getsid | sys_getsid | kernel/sys.c
125 | capget | sys_capget | kernel/capability.c
126 | capset | sys_capset | kernel/capability.c
127 | rt_sigpending | sys_rt_sigpending | kernel/signal.c
128 | rt_sigtimedwait | sys_rt_sigtimedwait | kernel/signal.c
129 | rt_sigqueueinfo | sys_rt_sigqueueinfo | kernel/signal.c
130 | rt_sigsuspend | sys_rt_sigsuspend | kernel/signal.c
131 | sigaltstack | sys_sigaltstack | kernel/signal.c
132 | utime | sys_utime | fs/utimes.c
133 | mknod | sys_mknod | fs/namei.c
134 | uselib |  | fs/exec.c
135 | personality | sys_personality | kernel/exec_domain.c
136 | ustat | sys_ustat | fs/statfs.c
137 | statfs | sys_statfs | fs/statfs.c
138 | fstatfs | sys_fstatfs | fs/statfs.c
139 | sysfs | sys_sysfs | fs/filesystems.c
140 | getpriority | sys_getpriority | kernel/sys.c
141 | setpriority | sys_setpriority | kernel/sys.c
142 | sched_setparam | sys_sched_setparam | kernel/sched/core.c
143 | sched_getparam | sys_sched_getparam | kernel/sched/core.c
144 | sched_setscheduler | sys_sched_setscheduler | kernel/sched/core.c
145 | sched_getscheduler | sys_sched_getscheduler | kernel/sched/core.c
146 | sched_get_priority_max | sys_sched_get_priority_max | kernel/sched/core.c
147 | sched_get_priority_min | sys_sched_get_priority_min | kernel/sched/core.c
148 | sched_rr_get_interval | sys_sched_rr_get_interval | kernel/sched/core.c
149 | mlock | sys_mlock | mm/mlock.c
150 | munlock | sys_munlock | mm/mlock.c
151 | mlockall | sys_mlockall | mm/mlock.c
152 | munlockall | sys_munlockall | mm/mlock.c
153 | vhangup | sys_vhangup | fs/open.c
154 | modify_ldt | sys_modify_ldt | arch/x86/um/ldt.c
155 | pivot_root | sys_pivot_root | fs/namespace.c
156 | _sysctl | sys_sysctl | kernel/sysctl_binary.c
157 | prctl | sys_prctl | kernel/sys.c
158 | arch_prctl | sys_arch_prctl | arch/x86/um/syscalls_64.c
159 | adjtimex | sys_adjtimex | kernel/time.c
160 | setrlimit | sys_setrlimit | kernel/sys.c
161 | chroot | sys_chroot | fs/open.c
162 | sync | sys_sync | fs/sync.c
163 | acct | sys_acct | kernel/acct.c
164 | settimeofday | sys_settimeofday | kernel/time.c
165 | mount | sys_mount | fs/namespace.c
166 | umount2 | sys_umount | fs/namespace.c
167 | swapon | sys_swapon | mm/swapfile.c
168 | swapoff | sys_swapoff | mm/swapfile.c
169 | reboot | sys_reboot | kernel/reboot.c
170 | sethostname | sys_sethostname | kernel/sys.c
171 | setdomainname | sys_setdomainname | kernel/sys.c
172 | iopl | stub_iopl | arch/x86/kernel/ioport.c
173 | ioperm | sys_ioperm | arch/x86/kernel/ioport.c
174 | create_module |  | NOT IMPLEMENTED
175 | init_module | sys_init_module | kernel/module.c
176 | delete_module | sys_delete_module | kernel/module.c
177 | get_kernel_syms |  | NOT IMPLEMENTED
178 | query_module |  | NOT IMPLEMENTED
179 | quotactl | sys_quotactl | fs/quota/quota.c
180 | nfsservctl |  | NOT IMPLEMENTED
181 | getpmsg |  | NOT IMPLEMENTED
182 | putpmsg |  | NOT IMPLEMENTED
183 | afs_syscall |  | NOT IMPLEMENTED
184 | tuxcall |  | NOT IMPLEMENTED
185 | security |  | NOT IMPLEMENTED
186 | gettid | sys_gettid | kernel/sys.c
187 | readahead | sys_readahead | mm/readahead.c
188 | setxattr | sys_setxattr | fs/xattr.c
189 | lsetxattr | sys_lsetxattr | fs/xattr.c
190 | fsetxattr | sys_fsetxattr | fs/xattr.c
191 | getxattr | sys_getxattr | fs/xattr.c
192 | lgetxattr | sys_lgetxattr | fs/xattr.c
193 | fgetxattr | sys_fgetxattr | fs/xattr.c
194 | listxattr | sys_listxattr | fs/xattr.c
195 | llistxattr | sys_llistxattr | fs/xattr.c
196 | flistxattr | sys_flistxattr | fs/xattr.c
197 | removexattr | sys_removexattr | fs/xattr.c
198 | lremovexattr | sys_lremovexattr | fs/xattr.c
199 | fremovexattr | sys_fremovexattr | fs/xattr.c
200 | tkill | sys_tkill | kernel/signal.c
201 | time | sys_time | kernel/time.c
202 | futex | sys_futex | kernel/futex.c
203 | sched_setaffinity | sys_sched_setaffinity | kernel/sched/core.c
204 | sched_getaffinity | sys_sched_getaffinity | kernel/sched/core.c
205 | set_thread_area |  | arch/x86/kernel/tls.c
206 | io_setup | sys_io_setup | fs/aio.c
207 | io_destroy | sys_io_destroy | fs/aio.c
208 | io_getevents | sys_io_getevents | fs/aio.c
209 | io_submit | sys_io_submit | fs/aio.c
210 | io_cancel | sys_io_cancel | fs/aio.c
211 | get_thread_area |  | arch/x86/kernel/tls.c
212 | lookup_dcookie | sys_lookup_dcookie | fs/dcookies.c
213 | epoll_create | sys_epoll_create | fs/eventpoll.c
214 | epoll_ctl_old |  | NOT IMPLEMENTED
215 | epoll_wait_old |  | NOT IMPLEMENTED
216 | remap_file_pages | sys_remap_file_pages | mm/fremap.c
217 | getdents64 | sys_getdents64 | fs/readdir.c
218 | set_tid_address | sys_set_tid_address | kernel/fork.c
219 | restart_syscall | sys_restart_syscall | kernel/signal.c
220 | semtimedop | sys_semtimedop | ipc/sem.c
221 | fadvise64 | sys_fadvise64 | mm/fadvise.c
222 | timer_create | sys_timer_create | kernel/posix-timers.c
223 | timer_settime | sys_timer_settime | kernel/posix-timers.c
224 | timer_gettime | sys_timer_gettime | kernel/posix-timers.c
225 | timer_getoverrun | sys_timer_getoverrun | kernel/posix-timers.c
226 | timer_delete | sys_timer_delete | kernel/posix-timers.c
227 | clock_settime | sys_clock_settime | kernel/posix-timers.c
228 | clock_gettime | sys_clock_gettime | kernel/posix-timers.c
229 | clock_getres | sys_clock_getres | kernel/posix-timers.c
230 | clock_nanosleep | sys_clock_nanosleep | kernel/posix-timers.c
231 | exit_group | sys_exit_group | kernel/exit.c
232 | epoll_wait | sys_epoll_wait | fs/eventpoll.c
233 | epoll_ctl | sys_epoll_ctl | fs/eventpoll.c
234 | tgkill | sys_tgkill | kernel/signal.c
235 | utimes | sys_utimes | fs/utimes.c
236 | vserver |  | NOT IMPLEMENTED
237 | mbind | sys_mbind | mm/mempolicy.c
238 | set_mempolicy | sys_set_mempolicy | mm/mempolicy.c
239 | get_mempolicy | sys_get_mempolicy | mm/mempolicy.c
240 | mq_open | sys_mq_open | ipc/mqueue.c
241 | mq_unlink | sys_mq_unlink | ipc/mqueue.c
242 | mq_timedsend | sys_mq_timedsend | ipc/mqueue.c
243 | mq_timedreceive | sys_mq_timedreceive | ipc/mqueue.c
244 | mq_notify | sys_mq_notify | ipc/mqueue.c
245 | mq_getsetattr | sys_mq_getsetattr | ipc/mqueue.c
246 | kexec_load | sys_kexec_load | kernel/kexec.c
247 | waitid | sys_waitid | kernel/exit.c
248 | add_key | sys_add_key | security/keys/keyctl.c
249 | request_key | sys_request_key | security/keys/keyctl.c
250 | keyctl | sys_keyctl | security/keys/keyctl.c
251 | ioprio_set | sys_ioprio_set | fs/ioprio.c
252 | ioprio_get | sys_ioprio_get | fs/ioprio.c
253 | inotify_init | sys_inotify_init | fs/notify/inotify/inotify_user.c
254 | inotify_add_watch | sys_inotify_add_watch | fs/notify/inotify/inotify_user.c
255 | inotify_rm_watch | sys_inotify_rm_watch | fs/notify/inotify/inotify_user.c
256 | migrate_pages | sys_migrate_pages | mm/mempolicy.c
257 | openat | sys_openat | fs/open.c
258 | mkdirat | sys_mkdirat | fs/namei.c
259 | mknodat | sys_mknodat | fs/namei.c
260 | fchownat | sys_fchownat | fs/open.c
261 | futimesat | sys_futimesat | fs/utimes.c
262 | newfstatat | sys_newfstatat | fs/stat.c
263 | unlinkat | sys_unlinkat | fs/namei.c
264 | renameat | sys_renameat | fs/namei.c
265 | linkat | sys_linkat | fs/namei.c
266 | symlinkat | sys_symlinkat | fs/namei.c
267 | readlinkat | sys_readlinkat | fs/stat.c
268 | fchmodat | sys_fchmodat | fs/open.c
269 | faccessat | sys_faccessat | fs/open.c
270 | pselect6 | sys_pselect6 | fs/select.c
271 | ppoll | sys_ppoll | fs/select.c
272 | unshare | sys_unshare | kernel/fork.c
273 | set_robust_list | sys_set_robust_list | kernel/futex.c
274 | get_robust_list | sys_get_robust_list | kernel/futex.c
275 | splice | sys_splice | fs/splice.c
276 | tee | sys_tee | fs/splice.c
277 | sync_file_range | sys_sync_file_range | fs/sync.c
278 | vmsplice | sys_vmsplice | fs/splice.c
279 | move_pages | sys_move_pages | mm/migrate.c
280 | utimensat | sys_utimensat | fs/utimes.c
281 | epoll_pwait | sys_epoll_pwait | fs/eventpoll.c
282 | signalfd | sys_signalfd | fs/signalfd.c
283 | timerfd_create | sys_timerfd_create | fs/timerfd.c
284 | eventfd | sys_eventfd | fs/eventfd.c
285 | fallocate | sys_fallocate | fs/open.c
286 | timerfd_settime | sys_timerfd_settime | fs/timerfd.c
287 | timerfd_gettime | sys_timerfd_gettime | fs/timerfd.c
288 | accept4 | sys_accept4 | net/socket.c
289 | signalfd4 | sys_signalfd4 | fs/signalfd.c
290 | eventfd2 | sys_eventfd2 | fs/eventfd.c
291 | epoll_create1 | sys_epoll_create1 | fs/eventpoll.c
292 | dup3 | sys_dup3 | fs/file.c
293 | pipe2 | sys_pipe2 | fs/pipe.c
294 | inotify_init1 | sys_inotify_init1 | fs/notify/inotify/inotify_user.c
295 | preadv | sys_preadv | fs/read_write.c
296 | pwritev | sys_pwritev | fs/read_write.c
297 | rt_tgsigqueueinfo | sys_rt_tgsigqueueinfo | kernel/signal.c
298 | perf_event_open | sys_perf_event_open | kernel/events/core.c
299 | recvmmsg | sys_recvmmsg | net/socket.c
300 | fanotify_init | sys_fanotify_init | fs/notify/fanotify/fanotify_user.c
301 | fanotify_mark | sys_fanotify_mark | fs/notify/fanotify/fanotify_user.c
302 | prlimit64 | sys_prlimit64 | kernel/sys.c
303 | name_to_handle_at | sys_name_to_handle_at | fs/fhandle.c
304 | open_by_handle_at | sys_open_by_handle_at | fs/fhandle.c
305 | clock_adjtime | sys_clock_adjtime | kernel/posix-timers.c
306 | syncfs | sys_syncfs | fs/sync.c
307 | sendmmsg | sys_sendmmsg | net/socket.c
308 | setns | sys_setns | kernel/nsproxy.c
309 | getcpu | sys_getcpu | kernel/sys.c
310 | process_vm_readv | sys_process_vm_readv | mm/process_vm_access.c
311 | process_vm_writev | sys_process_vm_writev | mm/process_vm_access.c
312 | kcmp | sys_kcmp | kernel/kcmp.c
313 | finit_module | sys_finit_module | kernel/module.c

### x86_32

id | name | args | eax | ebx | ecx | edx | esi | edi | defination
--- | --- | --- | --- | --- | --- | --- | --- | --- | ---
0 | sys_restart_syscall | (void) | 0x00 |  |  |  |  |  | kernel/signal.c
1 | sys_exit | (int error_code) | 0x01 | int error_code |  |  |  |  | kernel/exit.c
2 | sys_fork | (struct pt_regs *) | 0x02 | struct pt_regs * |  |  |  |  | arch/alpha/kernel/entry.S
3 | sys_read | (unsigned int fd, char __user *buf, size_t count) | 0x03 | unsigned int fd | char __user *buf | size_t count |  |  | fs/read_write.c
4 | sys_write | (unsigned int fd, const char __user *buf, size_t count) | 0x04 | unsigned int fd | const char __user *buf | size_t count |  |  | fs/read_write.c
5 | sys_open | (const char __user *filename, int flags, int mode) | 0x05 | const char __user *filename | int flags | int mode |  |  | fs/open.c
6 | sys_close | (unsigned int fd) | 0x06 | unsigned int fd |  |  |  |  | fs/open.c
7 | sys_waitpid | (pid_t pid, int __user *stat_addr, int options) | 0x07 | pid_t pid | int __user *stat_addr | int options |  |  | kernel/exit.c
8 | sys_creat | (const char __user *pathname, int mode) | 0x08 | const char __user *pathname | int mode |  |  |  | fs/open.c
9 | sys_link | (const char __user *oldname, const char __user *newname) | 0x09 | const char __user *oldname | const char __user *newname |  |  |  | fs/namei.c
10 | sys_unlink | (const char __user *pathname) | 0x0a | const char __user *pathname |  |  |  |  | fs/namei.c
11 | sys_execve | (char __user *, char __user *__user *, char __user *__user *, struct pt_regs *) | 0x0b | char __user * | char __user *__user * | char __user *__user * | struct pt_regs * |  | arch/alpha/kernel/entry.S
12 | sys_chdir | (const char __user *filename) | 0x0c | const char __user *filename |  |  |  |  | fs/open.c
13 | sys_time | (time_t __user *tloc) | 0x0d | time_t __user *tloc |  |  |  |  | kernel/posix-timers.c
14 | sys_mknod | (const char __user *filename, int mode, unsigned dev) | 0x0e | const char __user *filename | int mode | unsigned dev |  |  | fs/namei.c
15 | sys_chmod | (const char __user *filename, mode_t mode) | 0x0f | const char __user *filename | mode_t mode |  |  |  | fs/open.c
16 | sys_lchown16 | (const char __user *filename, old_uid_t user, old_gid_t group) | 0x10 | const char __user *filename | old_uid_t user | old_gid_t group |  |  | kernel/uid16.c
17 | not implemented |  | 0x11 |  |  |  |  |  | 
18 | sys_stat | (char __user *filename, struct __old_kernel_stat __user *statbuf) | 0x12 | char __user *filename | struct __old_kernel_stat __user *statbuf |  |  |  | fs/stat.c
19 | sys_lseek | (unsigned int fd, off_t offset, unsigned int origin) | 0x13 | unsigned int fd | off_t offset | unsigned int origin |  |  | fs/read_write.c
20 | sys_getpid | (void) | 0x14 |  |  |  |  |  | kernel/timer.c
21 | sys_mount | (char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data) | 0x15 | char __user *dev_name | char __user *dir_name | char __user *type | unsigned long flags | void __user *data | fs/namespace.c
22 | sys_oldumount | (char __user *name) | 0x16 | char __user *name |  |  |  |  | fs/namespace.c
23 | sys_setuid16 | (old_uid_t uid) | 0x17 | old_uid_t uid |  |  |  |  | kernel/uid16.c
24 | sys_getuid16 | (void) | 0x18 |  |  |  |  |  | kernel/uid16.c
25 | sys_stime | (time_t __user *tptr) | 0x19 | time_t __user *tptr |  |  |  |  | kernel/time.c
26 | sys_ptrace | (long request, long pid, long addr, long data) | 0x1a | long request | long pid | long addr | long data |  | kernel/ptrace.c
27 | sys_alarm | (unsigned int seconds) | 0x1b | unsigned int seconds |  |  |  |  | kernel/timer.c
28 | sys_fstat | (unsigned int fd, struct __old_kernel_stat __user *statbuf) | 0x1c | unsigned int fd | struct __old_kernel_stat __user *statbuf |  |  |  | fs/stat.c
29 | sys_pause | (void) | 0x1d |  |  |  |  |  | kernel/signal.c
30 | sys_utime | (char __user *filename, struct utimbuf __user *times) | 0x1e | char __user *filename | struct utimbuf __user *times |  |  |  | fs/utimes.c
31 | not implemented |  | 0x1f |  |  |  |  |  | 
32 | not implemented |  | 0x20 |  |  |  |  |  | 
33 | sys_access | (const char __user *filename, int mode) | 0x21 | const char __user *filename | int mode |  |  |  | fs/open.c
34 | sys_nice | (int increment) | 0x22 | int increment |  |  |  |  | kernel/sched.c
35 | not implemented |  | 0x23 |  |  |  |  |  | 
36 | sys_sync | (void) | 0x24 |  |  |  |  |  | fs/sync.c
37 | sys_kill | (int pid, int sig) | 0x25 | int pid | int sig |  |  |  | kernel/signal.c
38 | sys_rename | (const char __user *oldname, const char __user *newname) | 0x26 | const char __user *oldname | const char __user *newname |  |  |  | fs/namei.c
39 | sys_mkdir | (const char __user *pathname, int mode) | 0x27 | const char __user *pathname | int mode |  |  |  | fs/namei.c
40 | sys_rmdir | (const char __user *pathname) | 0x28 | const char __user *pathname |  |  |  |  | fs/namei.c
41 | sys_dup | (unsigned int fildes) | 0x29 | unsigned int fildes |  |  |  |  | fs/fcntl.c
42 | sys_pipe | (int __user *fildes) | 0x2a | int __user *fildes |  |  |  |  | fs/pipe.c
43 | sys_times | (struct tms __user *tbuf) | 0x2b | struct tms __user *tbuf |  |  |  |  | kernel/sys.c
44 | not implemented |  | 0x2c |  |  |  |  |  | 
45 | sys_brk | (unsigned long brk) | 0x2d | unsigned long brk |  |  |  |  | mm/mmap.c
46 | sys_setgid16 | (old_gid_t gid) | 0x2e | old_gid_t gid |  |  |  |  | kernel/uid16.c
47 | sys_getgid16 | (void) | 0x2f |  |  |  |  |  | kernel/uid16.c
48 | sys_signal | (int sig, __sighandler_t handler) | 0x30 | int sig | __sighandler_t handler |  |  |  | kernel/signal.c
49 | sys_geteuid16 | (void) | 0x31 |  |  |  |  |  | kernel/uid16.c
50 | sys_getegid16 | (void) | 0x32 |  |  |  |  |  | kernel/uid16.c
51 | sys_acct | (const char __user *name) | 0x33 | const char __user *name |  |  |  |  | kernel/acct.c
52 | sys_umount | (char __user *name, int flags) | 0x34 | char __user *name | int flags |  |  |  | fs/namespace.c
53 | not implemented |  | 0x35 |  |  |  |  |  | 
54 | sys_ioctl | (unsigned int fd, unsigned int cmd, unsigned long arg) | 0x36 | unsigned int fd | unsigned int cmd | unsigned long arg |  |  | fs/ioctl.c
55 | sys_fcntl | (unsigned int fd, unsigned int cmd, unsigned long arg) | 0x37 | unsigned int fd | unsigned int cmd | unsigned long arg |  |  | fs/fcntl.c
56 | not implemented |  | 0x38 |  |  |  |  |  | 
57 | sys_setpgid | (pid_t pid, pid_t pgid) | 0x39 | pid_t pid | pid_t pgid |  |  |  | kernel/sys.c
58 | not implemented |  | 0x3a |  |  |  |  |  | 
59 | sys_olduname | (struct oldold_utsname __user *) | 0x3b | struct oldold_utsname __user * |  |  |  |  | kernel/sys.c
60 | sys_umask | (int mask) | 0x3c | int mask |  |  |  |  | kernel/sys.c
61 | sys_chroot | (const char __user *filename) | 0x3d | const char __user *filename |  |  |  |  | fs/open.c
62 | sys_ustat | (unsigned dev, struct ustat __user *ubuf) | 0x3e | unsigned dev | struct ustat __user *ubuf |  |  |  | fs/statfs.c
63 | sys_dup2 | (unsigned int oldfd, unsigned int newfd) | 0x3f | unsigned int oldfd | unsigned int newfd |  |  |  | fs/fcntl.c
64 | sys_getppid | (void) | 0x40 |  |  |  |  |  | kernel/timer.c
65 | sys_getpgrp | (void) | 0x41 |  |  |  |  |  | kernel/sys.c
66 | sys_setsid | (void) | 0x42 |  |  |  |  |  | kernel/sys.c
67 | sys_sigaction | (int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact) | 0x43 | int sig | const struct old_sigaction __user *act | struct old_sigaction __user *oact |  |  | arch/mips/kernel/signal.c
68 | sys_sgetmask | (void) | 0x44 |  |  |  |  |  | kernel/signal.c
69 | sys_ssetmask | (int newmask) | 0x45 | int newmask |  |  |  |  | kernel/signal.c
70 | sys_setreuid16 | (old_uid_t ruid, old_uid_t euid) | 0x46 | old_uid_t ruid | old_uid_t euid |  |  |  | kernel/uid16.c
71 | sys_setregid16 | (old_gid_t rgid, old_gid_t egid) | 0x47 | old_gid_t rgid | old_gid_t egid |  |  |  | kernel/uid16.c
72 | sys_sigsuspend | (int history0, int history1, old_sigset_t mask) | 0x48 | int history0 | int history1 | old_sigset_t mask |  |  | arch/s390/kernel/signal.c
73 | sys_sigpending | (old_sigset_t __user *set) | 0x49 | old_sigset_t __user *set |  |  |  |  | kernel/signal.c
74 | sys_sethostname | (char __user *name, int len) | 0x4a | char __user *name | int len |  |  |  | kernel/sys.c
75 | sys_setrlimit | (unsigned int resource, struct rlimit __user *rlim) | 0x4b | unsigned int resource | struct rlimit __user *rlim |  |  |  | kernel/sys.c
76 | sys_old_getrlimit | (unsigned int resource, struct rlimit __user *rlim) | 0x4c | unsigned int resource | struct rlimit __user *rlim |  |  |  | kernel/sys.c
77 | sys_getrusage | (int who, struct rusage __user *ru) | 0x4d | int who | struct rusage __user *ru |  |  |  | kernel/sys.c
78 | sys_gettimeofday | (struct timeval __user *tv, struct timezone __user *tz) | 0x4e | struct timeval __user *tv | struct timezone __user *tz |  |  |  | kernel/time.c
79 | sys_settimeofday | (struct timeval __user *tv, struct timezone __user *tz) | 0x4f | struct timeval __user *tv | struct timezone __user *tz |  |  |  | kernel/time.c
80 | sys_getgroups16 | (int gidsetsize, old_gid_t __user *grouplist) | 0x50 | int gidsetsize | old_gid_t __user *grouplist |  |  |  | kernel/uid16.c
81 | sys_setgroups16 | (int gidsetsize, old_gid_t __user *grouplist) | 0x51 | int gidsetsize | old_gid_t __user *grouplist |  |  |  | kernel/uid16.c
82 | sys_old_select | (struct sel_arg_struct __user *arg) | 0x52 | struct sel_arg_struct __user *arg |  |  |  |  | fs/select.c
83 | sys_symlink | (const char __user *old, const char __user *new) | 0x53 | const char __user *old | const char __user *new |  |  |  | fs/namei.c
84 | sys_lstat | (char __user *filename, struct __old_kernel_stat __user *statbuf) | 0x54 | char __user *filename | struct __old_kernel_stat __user *statbuf |  |  |  | fs/stat.c
85 | sys_readlink | (const char __user *path, char __user *buf, int bufsiz) | 0x55 | const char __user *path | char __user *buf | int bufsiz |  |  | fs/stat.c
86 | sys_uselib | (const char __user *library) | 0x56 | const char __user *library |  |  |  |  | fs/exec.c
87 | sys_swapon | (const char __user *specialfile, int swap_flags) | 0x57 | const char __user *specialfile | int swap_flags |  |  |  | mm/swapfile.c
88 | sys_reboot | (int magic1, int magic2, unsigned int cmd, void __user *arg) | 0x58 | int magic1 | int magic2 | unsigned int cmd | void __user *arg |  | kernel/sys.c
89 | sys_old_readdir | (unsigned int, struct old_linux_dirent __user *, unsigned int) | 0x59 | unsigned int | struct old_linux_dirent __user * | unsigned int |  |  | fs/readdir.c
90 | sys_old_mmap | (struct mmap_arg_struct __user *arg) | 0x5a | struct mmap_arg_struct __user *arg |  |  |  |  | mm/mmap.c
91 | sys_munmap | (unsigned long addr, size_t len) | 0x5b | unsigned long addr | size_t len |  |  |  | mm/mmap.c
92 | sys_truncate | (const char __user *path, long length) | 0x5c | const char __user *path | long length |  |  |  | fs/open.c
93 | sys_ftruncate | (unsigned int fd, unsigned long length) | 0x5d | unsigned int fd | unsigned long length |  |  |  | fs/open.c
94 | sys_fchmod | (unsigned int fd, mode_t mode) | 0x5e | unsigned int fd | mode_t mode |  |  |  | fs/open.c
95 | sys_fchown16 | (unsigned int fd, old_uid_t user, old_gid_t group) | 0x5f | unsigned int fd | old_uid_t user | old_gid_t group |  |  | kernel/uid16.c
96 | sys_getpriority | (int which, int who) | 0x60 | int which | int who |  |  |  | kernel/sys.c
97 | sys_setpriority | (int which, int who, int niceval) | 0x61 | int which | int who | int niceval |  |  | kernel/sys.c
98 | not implemented |  | 0x62 |  |  |  |  |  | 
99 | sys_statfs | (const char __user * path, struct statfs __user *buf) | 0x63 | const char __user * path | struct statfs __user *buf |  |  |  | fs/statfs.c
100 | sys_fstatfs | (unsigned int fd, struct statfs __user *buf) | 0x64 | unsigned int fd | struct statfs __user *buf |  |  |  | fs/statfs.c
101 | sys_ioperm | (unsigned long, unsigned long, int) | 0x65 | unsigned long | unsigned long | int |  |  | not found
102 | sys_socketcall | (int call, unsigned long __user *args) | 0x66 | int call | unsigned long __user *args |  |  |  | net/socket.c
103 | sys_syslog | (int type, char __user *buf, int len) | 0x67 | int type | char __user *buf | int len |  |  | kernel/printk.c
104 | sys_setitimer | (int which, struct itimerval __user *value, struct itimerval __user *ovalue) | 0x68 | int which | struct itimerval __user *value | struct itimerval __user *ovalue |  |  | kernel/itimer.c
105 | sys_getitimer | (int which, struct itimerval __user *value) | 0x69 | int which | struct itimerval __user *value |  |  |  | kernel/itimer.c
106 | sys_newstat | (char __user *filename, struct stat __user *statbuf) | 0x6a | char __user *filename | struct stat __user *statbuf |  |  |  | fs/stat.c
107 | sys_newlstat | (char __user *filename, struct stat __user *statbuf) | 0x6b | char __user *filename | struct stat __user *statbuf |  |  |  | fs/stat.c
108 | sys_newfstat | (unsigned int fd, struct stat __user *statbuf) | 0x6c | unsigned int fd | struct stat __user *statbuf |  |  |  | fs/stat.c
109 | sys_uname | (struct old_utsname __user *) | 0x6d | struct old_utsname __user * |  |  |  |  | kernel/sys.c
110 | sys_iopl | (unsigned int, struct pt_regs *) | 0x6e | unsigned int | struct pt_regs * |  |  |  | not found
111 | sys_vhangup | (void) | 0x6f |  |  |  |  |  | fs/open.c
112 | not implemented |  | 0x70 |  |  |  |  |  | 
113 | sys_vm86old | (struct vm86_struct __user *, struct pt_regs *) | 0x71 | struct vm86_struct __user * | struct pt_regs * |  |  |  | not found
114 | sys_wait4 | (pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru) | 0x72 | pid_t pid | int __user *stat_addr | int options | struct rusage __user *ru |  | kernel/exit.c
115 | sys_swapoff | (const char __user *specialfile) | 0x73 | const char __user *specialfile |  |  |  |  | mm/swapfile.c
116 | sys_sysinfo | (struct sysinfo __user *info) | 0x74 | struct sysinfo __user *info |  |  |  |  | kernel/timer.c
117 | sys_ipc | (unsigned int call, int first, unsigned long second, unsigned long third, void __user *ptr, long fifth) | 0x75 |  |  |  |  |  | ipc/syscall.c
118 | sys_fsync | (unsigned int fd) | 0x76 | unsigned int fd |  |  |  |  | fs/sync.c
119 | sys_sigreturn | (struct pt_regs *regs) | 0x77 | struct pt_regs *regs |  |  |  |  | arch/alpha/kernel/entry.S
120 | sys_clone | (unsigned long, unsigned long, unsigned long, unsigned long, struct pt_regs *) | 0x78 | unsigned long | unsigned long | unsigned long | unsigned long | struct pt_regs * | arch/alpha/kernel/entry.S
121 | sys_setdomainname | (char __user *name, int len) | 0x79 | char __user *name | int len |  |  |  | kernel/sys.c
122 | sys_newuname | (struct new_utsname __user *name) | 0x7a | struct new_utsname __user *name |  |  |  |  | kernel/sys.c
123 | sys_modify_ldt | (int, void __user *, unsigned long) | 0x7b | int | void __user * | unsigned long |  |  | not found
124 | sys_adjtimex | (struct timex __user *txc_p) | 0x7c | struct timex __user *txc_p |  |  |  |  | kernel/time.c
125 | sys_mprotect | (unsigned long start, size_t len, unsigned long prot) | 0x7d | unsigned long start | size_t len | unsigned long prot |  |  | mm/mprotect.c
126 | sys_sigprocmask | (int how, old_sigset_t __user *set, old_sigset_t __user *oset) | 0x7e | int how | old_sigset_t __user *set | old_sigset_t __user *oset |  |  | kernel/signal.c
127 | not implemented |  | 0x7f |  |  |  |  |  | 
128 | sys_init_module | (void __user *umod, unsigned long len, const char __user *uargs) | 0x80 | void __user *umod | unsigned long len | const char __user *uargs |  |  | kernel/module.c
129 | sys_delete_module | (const char __user *name_user, unsigned int flags) | 0x81 | const char __user *name_user | unsigned int flags |  |  |  | kernel/module.c
130 | not implemented |  | 0x82 |  |  |  |  |  | 
131 | sys_quotactl | (unsigned int cmd, const char __user *special, qid_t id, void __user *addr) | 0x83 | unsigned int cmd | const char __user *special | qid_t id | void __user *addr |  | fs/quota/quota.c
132 | sys_getpgid | (pid_t pid) | 0x84 | pid_t pid |  |  |  |  | kernel/sys.c
133 | sys_fchdir | (unsigned int fd) | 0x85 | unsigned int fd |  |  |  |  | fs/open.c
134 | sys_bdflush | (int func, long data) | 0x86 | int func | long data |  |  |  | fs/buffer.c
135 | sys_sysfs | (int option, unsigned long arg1, unsigned long arg2) | 0x87 | int option | unsigned long arg1 | unsigned long arg2 |  |  | fs/filesystems.c
136 | sys_personality | (unsigned int personality) | 0x88 | unsigned int personality |  |  |  |  | kernel/exec_domain.c
137 | not implemented |  | 0x89 |  |  |  |  |  | 
138 | sys_setfsuid16 | (old_uid_t uid) | 0x8a | old_uid_t uid |  |  |  |  | kernel/uid16.c
139 | sys_setfsgid16 | (old_gid_t gid) | 0x8b | old_gid_t gid |  |  |  |  | kernel/uid16.c
140 | sys_llseek | (unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int origin) | 0x8c | unsigned int fd | unsigned long offset_high | unsigned long offset_low | loff_t __user *result | unsigned int origin | fs/read_write.c
141 | sys_getdents | (unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) | 0x8d | unsigned int fd | struct linux_dirent __user *dirent | unsigned int count |  |  | fs/readdir.c
142 | sys_select | (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) | 0x8e | int n | fd_set __user *inp | fd_set __user *outp | fd_set __user *exp | struct timeval __user *tvp | fs/select.c
143 | sys_flock | (unsigned int fd, unsigned int cmd) | 0x8f | unsigned int fd | unsigned int cmd |  |  |  | fs/locks.c
144 | sys_msync | (unsigned long start, size_t len, int flags) | 0x90 | unsigned long start | size_t len | int flags |  |  | mm/msync.c
145 | sys_readv | (unsigned long fd, const struct iovec __user *vec, unsigned long vlen) | 0x91 | unsigned long fd | const struct iovec __user *vec | unsigned long vlen |  |  | fs/read_write.c
146 | sys_writev | (unsigned long fd, const struct iovec __user *vec, unsigned long vlen) | 0x92 | unsigned long fd | const struct iovec __user *vec | unsigned long vlen |  |  | fs/read_write.c
147 | sys_getsid | (pid_t pid) | 0x93 | pid_t pid |  |  |  |  | kernel/sys.c
148 | sys_fdatasync | (unsigned int fd) | 0x94 | unsigned int fd |  |  |  |  | fs/sync.c
149 | sys_sysctl | (struct __sysctl_args __user *args) | 0x95 | struct __sysctl_args __user *args |  |  |  |  | kernel/sysctl_binary.c
150 | sys_mlock | (unsigned long start, size_t len) | 0x96 | unsigned long start | size_t len |  |  |  | mm/mlock.c
151 | sys_munlock | (unsigned long start, size_t len) | 0x97 | unsigned long start | size_t len |  |  |  | mm/mlock.c
152 | sys_mlockall | (int flags) | 0x98 | int flags |  |  |  |  | mm/mlock.c
153 | sys_munlockall | (void) | 0x99 |  |  |  |  |  | mm/mlock.c
154 | sys_sched_setparam | (pid_t pid, struct sched_param __user *param) | 0x9a | pid_t pid | struct sched_param __user *param |  |  |  | kernel/sched.c
155 | sys_sched_getparam | (pid_t pid, struct sched_param __user *param) | 0x9b | pid_t pid | struct sched_param __user *param |  |  |  | kernel/sched.c
156 | sys_sched_setscheduler | (pid_t pid, int policy, struct sched_param __user *param) | 0x9c | pid_t pid | int policy | struct sched_param __user *param |  |  | kernel/sched.c
157 | sys_sched_getscheduler | (pid_t pid) | 0x9d | pid_t pid |  |  |  |  | kernel/sched.c
158 | sys_sched_yield | (void) | 0x9e |  |  |  |  |  | kernel/sched.c
159 | sys_sched_get_priority_max | (int policy) | 0x9f | int policy |  |  |  |  | kernel/sched.c
160 | sys_sched_get_priority_min | (int policy) | 0xa0 | int policy |  |  |  |  | kernel/sched.c
161 | sys_sched_rr_get_interval | (pid_t pid, struct timespec __user *interval) | 0xa1 | pid_t pid | struct timespec __user *interval |  |  |  | kernel/sched.c
162 | sys_nanosleep | (struct timespec __user *rqtp, struct timespec __user *rmtp) | 0xa2 | struct timespec __user *rqtp | struct timespec __user *rmtp |  |  |  | kernel/hrtimer.c
163 | sys_mremap | (unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr) | 0xa3 | unsigned long addr | unsigned long old_len | unsigned long new_len | unsigned long flags | unsigned long new_addr | mm/mremap.c
164 | sys_setresuid16 | (old_uid_t ruid, old_uid_t euid, old_uid_t suid) | 0xa4 | old_uid_t ruid | old_uid_t euid | old_uid_t suid |  |  | kernel/uid16.c
165 | sys_getresuid16 | (old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid) | 0xa5 | old_uid_t __user *ruid | old_uid_t __user *euid | old_uid_t __user *suid |  |  | kernel/uid16.c
166 | sys_vm86 | (unsigned long, unsigned long, struct pt_regs *) | 0xa6 | unsigned long | unsigned long | struct pt_regs * |  |  | not found
167 | not implemented |  | 0xa7 |  |  |  |  |  | 
168 | sys_poll | (struct pollfd __user *ufds, unsigned int nfds, long timeout) | 0xa8 | struct pollfd __user *ufds | unsigned int nfds | long timeout |  |  | fs/select.c
169 | sys_nfsservctl | (int cmd, struct nfsctl_arg __user *arg, void __user *res) | 0xa9 | int cmd | struct nfsctl_arg __user *arg | void __user *res |  |  | fs/nfsctl.c
170 | sys_setresgid16 | (old_gid_t rgid, old_gid_t egid, old_gid_t sgid) | 0xaa | old_gid_t rgid | old_gid_t egid | old_gid_t sgid |  |  | kernel/uid16.c
171 | sys_getresgid16 | (old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid) | 0xab | old_gid_t __user *rgid | old_gid_t __user *egid | old_gid_t __user *sgid |  |  | kernel/uid16.c
172 | sys_prctl | (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) | 0xac | int option | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | kernel/sys.c
173 | sys_rt_sigreturn | (struct pt_regs *) | 0xad | struct pt_regs * |  |  |  |  | arch/alpha/kernel/entry.S
174 | sys_rt_sigaction | (int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize) | 0xae | int sig | const struct sigaction __user *act | struct sigaction __user *oact | size_t sigsetsize |  | kernel/signal.c
175 | sys_rt_sigprocmask | (int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize) | 0xaf | int how | sigset_t __user *set | sigset_t __user *oset | size_t sigsetsize |  | kernel/signal.c
176 | sys_rt_sigpending | (sigset_t __user *set, size_t sigsetsize) | 0xb0 | sigset_t __user *set | size_t sigsetsize |  |  |  | kernel/signal.c
177 | sys_rt_sigtimedwait | (const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize) | 0xb1 | const sigset_t __user *uthese | siginfo_t __user *uinfo | const struct timespec __user *uts | size_t sigsetsize |  | kernel/signal.c
178 | sys_rt_sigqueueinfo | (int pid, int sig, siginfo_t __user *uinfo) | 0xb2 | int pid | int sig | siginfo_t __user *uinfo |  |  | kernel/signal.c
179 | sys_rt_sigsuspend | (sigset_t __user *unewset, size_t sigsetsize) | 0xb3 | sigset_t __user *unewset | size_t sigsetsize |  |  |  | kernel/signal.c
180 | sys_pread64 | (unsigned int fd, char __user *buf, size_t count, loff_t pos) | 0xb4 | unsigned int fd | char __user *buf | size_t count | loff_t pos |  | not found
181 | sys_pwrite64 | (unsigned int fd, const char __user *buf, size_t count, loff_t pos) | 0xb5 | unsigned int fd | const char __user *buf | size_t count | loff_t pos |  | not found
182 | sys_chown16 | (const char __user *filename, old_uid_t user, old_gid_t group) | 0xb6 | const char __user *filename | old_uid_t user | old_gid_t group |  |  | kernel/uid16.c
183 | sys_getcwd | (char __user *buf, unsigned long size) | 0xb7 | char __user *buf | unsigned long size |  |  |  | fs/dcache.c
184 | sys_capget | (cap_user_header_t header, cap_user_data_t dataptr) | 0xb8 | cap_user_header_t header | cap_user_data_t dataptr |  |  |  | kernel/capability.c
185 | sys_capset | (cap_user_header_t header, const cap_user_data_t data) | 0xb9 | cap_user_header_t header | const cap_user_data_t data |  |  |  | kernel/capability.c
186 | sys_sigaltstack | (const stack_t __user *, stack_t __user *, struct pt_regs *) | 0xba | const stack_t __user * | stack_t __user * | struct pt_regs * |  |  | arch/alpha/kernel/signal.c
187 | sys_sendfile | (int out_fd, int in_fd, off_t __user *offset, size_t count) | 0xbb | int out_fd | int in_fd | off_t __user *offset | size_t count |  | fs/read_write.c
188 | not implemented |  | 0xbc |  |  |  |  |  | 
189 | not implemented |  | 0xbd |  |  |  |  |  | 
190 | sys_vfork | (struct pt_regs *) | 0xbe | struct pt_regs * |  |  |  |  | arch/alpha/kernel/entry.S
191 | sys_getrlimit | (unsigned int resource, struct rlimit __user *rlim) | 0xbf | unsigned int resource | struct rlimit __user *rlim |  |  |  | kernel/sys.c
192 | sys_mmap_pgoff | (unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff) | 0xc0 |  |  |  |  |  | mm/mmap.c
193 | sys_truncate64 | (const char __user *path, loff_t length) | 0xc1 | const char __user *path | loff_t length |  |  |  | not found
194 | sys_ftruncate64 | (unsigned int fd, loff_t length) | 0xc2 | unsigned int fd | loff_t length |  |  |  | not found
195 | sys_stat64 | (char __user *filename, struct stat64 __user *statbuf) | 0xc3 | char __user *filename | struct stat64 __user *statbuf |  |  |  | fs/stat.c
196 | sys_lstat64 | (char __user *filename, struct stat64 __user *statbuf) | 0xc4 | char __user *filename | struct stat64 __user *statbuf |  |  |  | fs/stat.c
197 | sys_fstat64 | (unsigned long fd, struct stat64 __user *statbuf) | 0xc5 | unsigned long fd | struct stat64 __user *statbuf |  |  |  | fs/stat.c
198 | sys_lchown | (const char __user *filename, uid_t user, gid_t group) | 0xc6 | const char __user *filename | uid_t user | gid_t group |  |  | fs/open.c
199 | sys_getuid | (void) | 0xc7 |  |  |  |  |  | kernel/timer.c
200 | sys_getgid | (void) | 0xc8 |  |  |  |  |  | kernel/timer.c
201 | sys_geteuid | (void) | 0xc9 |  |  |  |  |  | kernel/timer.c
202 | sys_getegid | (void) | 0xca |  |  |  |  |  | kernel/timer.c
203 | sys_setreuid | (uid_t ruid, uid_t euid) | 0xcb | uid_t ruid | uid_t euid |  |  |  | kernel/sys.c
204 | sys_setregid | (gid_t rgid, gid_t egid) | 0xcc | gid_t rgid | gid_t egid |  |  |  | kernel/sys.c
205 | sys_getgroups | (int gidsetsize, gid_t __user *grouplist) | 0xcd | int gidsetsize | gid_t __user *grouplist |  |  |  | kernel/groups.c
206 | sys_setgroups | (int gidsetsize, gid_t __user *grouplist) | 0xce | int gidsetsize | gid_t __user *grouplist |  |  |  | kernel/groups.c
207 | sys_fchown | (unsigned int fd, uid_t user, gid_t group) | 0xcf | unsigned int fd | uid_t user | gid_t group |  |  | fs/open.c
208 | sys_setresuid | (uid_t ruid, uid_t euid, uid_t suid) | 0xd0 | uid_t ruid | uid_t euid | uid_t suid |  |  | kernel/sys.c
209 | sys_getresuid | (uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) | 0xd1 | uid_t __user *ruid | uid_t __user *euid | uid_t __user *suid |  |  | kernel/sys.c
210 | sys_setresgid | (gid_t rgid, gid_t egid, gid_t sgid) | 0xd2 | gid_t rgid | gid_t egid | gid_t sgid |  |  | kernel/sys.c
211 | sys_getresgid | (gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) | 0xd3 | gid_t __user *rgid | gid_t __user *egid | gid_t __user *sgid |  |  | kernel/sys.c
212 | sys_chown | (const char __user *filename, uid_t user, gid_t group) | 0xd4 | const char __user *filename | uid_t user | gid_t group |  |  | fs/open.c
213 | sys_setuid | (uid_t uid) | 0xd5 | uid_t uid |  |  |  |  | kernel/sys.c
214 | sys_setgid | (gid_t gid) | 0xd6 | gid_t gid |  |  |  |  | kernel/sys.c
215 | sys_setfsuid | (uid_t uid) | 0xd7 | uid_t uid |  |  |  |  | kernel/sys.c
216 | sys_setfsgid | (gid_t gid) | 0xd8 | gid_t gid |  |  |  |  | kernel/sys.c
217 | sys_pivot_root | (const char __user *new_root, const char __user *put_old) | 0xd9 | const char __user *new_root | const char __user *put_old |  |  |  | fs/namespace.c
218 | sys_mincore | (unsigned long start, size_t len, unsigned char __user * vec) | 0xda | unsigned long start | size_t len | unsigned char __user * vec |  |  | mm/mincore.c
219 | sys_madvise | (unsigned long start, size_t len, int behavior) | 0xdb | unsigned long start | size_t len | int behavior |  |  | mm/madvise.c
220 | sys_getdents64 | (unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count) | 0xdc | unsigned int fd | struct linux_dirent64 __user *dirent | unsigned int count |  |  | fs/readdir.c
221 | sys_fcntl64 | (unsigned int fd, unsigned int cmd, unsigned long arg) | 0xdd | unsigned int fd | unsigned int cmd | unsigned long arg |  |  | fs/fcntl.c
222 | not implemented |  | 0xde |  |  |  |  |  | 
223 | not implemented |  | 0xdf |  |  |  |  |  | 
224 | sys_gettid | (void) | 0xe0 |  |  |  |  |  | kernel/timer.c
225 | sys_readahead | (int fd, loff_t offset, size_t count) | 0xe1 | int fd | loff_t offset | size_t count |  |  | not found
226 | sys_setxattr | (const char __user *path, const char __user *name, const void __user *value, size_t size, int flags) | 0xe2 | const char __user *path | const char __user *name | const void __user *value | size_t size | int flags | fs/xattr.c
227 | sys_lsetxattr | (const char __user *path, const char __user *name, const void __user *value, size_t size, int flags) | 0xe3 | const char __user *path | const char __user *name | const void __user *value | size_t size | int flags | fs/xattr.c
228 | sys_fsetxattr | (int fd, const char __user *name, const void __user *value, size_t size, int flags) | 0xe4 | int fd | const char __user *name | const void __user *value | size_t size | int flags | fs/xattr.c
229 | sys_getxattr | (const char __user *path, const char __user *name, void __user *value, size_t size) | 0xe5 | const char __user *path | const char __user *name | void __user *value | size_t size |  | fs/xattr.c
230 | sys_lgetxattr | (const char __user *path, const char __user *name, void __user *value, size_t size) | 0xe6 | const char __user *path | const char __user *name | void __user *value | size_t size |  | fs/xattr.c
231 | sys_fgetxattr | (int fd, const char __user *name, void __user *value, size_t size) | 0xe7 | int fd | const char __user *name | void __user *value | size_t size |  | fs/xattr.c
232 | sys_listxattr | (const char __user *path, char __user *list, size_t size) | 0xe8 | const char __user *path | char __user *list | size_t size |  |  | fs/xattr.c
233 | sys_llistxattr | (const char __user *path, char __user *list, size_t size) | 0xe9 | const char __user *path | char __user *list | size_t size |  |  | fs/xattr.c
234 | sys_flistxattr | (int fd, char __user *list, size_t size) | 0xea | int fd | char __user *list | size_t size |  |  | fs/xattr.c
235 | sys_removexattr | (const char __user *path, const char __user *name) | 0xeb | const char __user *path | const char __user *name |  |  |  | fs/xattr.c
236 | sys_lremovexattr | (const char __user *path, const char __user *name) | 0xec | const char __user *path | const char __user *name |  |  |  | fs/xattr.c
237 | sys_fremovexattr | (int fd, const char __user *name) | 0xed | int fd | const char __user *name |  |  |  | fs/xattr.c
238 | sys_tkill | (int pid, int sig) | 0xee | int pid | int sig |  |  |  | kernel/signal.c
239 | sys_sendfile64 | (int out_fd, int in_fd, loff_t __user *offset, size_t count) | 0xef | int out_fd | int in_fd | loff_t __user *offset | size_t count |  | fs/read_write.c
240 | sys_futex | (u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3) | 0xf0 |  |  |  |  |  | kernel/futex.c
241 | sys_sched_setaffinity | (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) | 0xf1 | pid_t pid | unsigned int len | unsigned long __user *user_mask_ptr |  |  | kernel/sched.c
242 | sys_sched_getaffinity | (pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr) | 0xf2 | pid_t pid | unsigned int len | unsigned long __user *user_mask_ptr |  |  | kernel/sched.c
243 | sys_set_thread_area | (struct user_desc __user *) | 0xf3 | struct user_desc __user * |  |  |  |  | arch/mips/kernel/syscall.c
244 | sys_get_thread_area | (struct user_desc __user *) | 0xf4 | struct user_desc __user * |  |  |  |  | not found
245 | sys_io_setup | (unsigned nr_reqs, aio_context_t __user *ctx) | 0xf5 | unsigned nr_reqs | aio_context_t __user *ctx |  |  |  | fs/aio.c
246 | sys_io_destroy | (aio_context_t ctx) | 0xf6 | aio_context_t ctx |  |  |  |  | fs/aio.c
247 | sys_io_getevents | (aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout) | 0xf7 | aio_context_t ctx_id | long min_nr | long nr | struct io_event __user *events | struct timespec __user *timeout | fs/aio.c
248 | sys_io_submit | (aio_context_t, long, struct iocb __user * __user *) | 0xf8 | aio_context_t | long | struct iocb __user * __user * |  |  | fs/aio.c
249 | sys_io_cancel | (aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result) | 0xf9 | aio_context_t ctx_id | struct iocb __user *iocb | struct io_event __user *result |  |  | fs/aio.c
250 | sys_fadvise64 | (int fd, loff_t offset, size_t len, int advice) | 0xfa | int fd | loff_t offset | size_t len | int advice |  | not found
251 | not implemented |  | 0xfb |  |  |  |  |  | 
252 | sys_exit_group | (int error_code) | 0xfc | int error_code |  |  |  |  | kernel/exit.c
253 | sys_lookup_dcookie | (u64 cookie64, char __user *buf, size_t len) | 0xfd | u64 cookie64 | char __user *buf | size_t len |  |  | not found
254 | sys_epoll_create | (int size) | 0xfe | int size |  |  |  |  | fs/eventpoll.c
255 | sys_epoll_ctl | (int epfd, int op, int fd, struct epoll_event __user *event) | 0xff | int epfd | int op | int fd | struct epoll_event __user *event |  | fs/eventpoll.c
256 | sys_epoll_wait | (int epfd, struct epoll_event __user *events, int maxevents, int timeout) | 0x100 | int epfd | struct epoll_event __user *events | int maxevents | int timeout |  | fs/eventpoll.c
257 | sys_remap_file_pages | (unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) | 0x101 | unsigned long start | unsigned long size | unsigned long prot | unsigned long pgoff | unsigned long flags | mm/fremap.c
258 | sys_set_tid_address | (int __user *tidptr) | 0x102 | int __user *tidptr |  |  |  |  | kernel/fork.c
259 | sys_timer_create | (clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id) | 0x103 | clockid_t which_clock | struct sigevent __user *timer_event_spec | timer_t __user * created_timer_id |  |  | kernel/posix-timers.c
260 | sys_timer_settime | (timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting) | 0x104 | timer_t timer_id | int flags | const struct itimerspec __user *new_setting | struct itimerspec __user *old_setting |  | kernel/posix-timers.c
261 | sys_timer_gettime | (timer_t timer_id, struct itimerspec __user *setting) | 0x105 | timer_t timer_id | struct itimerspec __user *setting |  |  |  | kernel/posix-timers.c
262 | sys_timer_getoverrun | (timer_t timer_id) | 0x106 | timer_t timer_id |  |  |  |  | kernel/posix-timers.c
263 | sys_timer_delete | (timer_t timer_id) | 0x107 | timer_t timer_id |  |  |  |  | kernel/posix-timers.c
264 | sys_clock_settime | (clockid_t which_clock, const struct timespec __user *tp) | 0x108 | clockid_t which_clock | const struct timespec __user *tp |  |  |  | kernel/posix-timers.c
265 | sys_clock_gettime | (clockid_t which_clock, struct timespec __user *tp) | 0x109 | clockid_t which_clock | struct timespec __user *tp |  |  |  | kernel/posix-timers.c
266 | sys_clock_getres | (clockid_t which_clock, struct timespec __user *tp) | 0x10a | clockid_t which_clock | struct timespec __user *tp |  |  |  | kernel/posix-timers.c
267 | sys_clock_nanosleep | (clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp) | 0x10b | clockid_t which_clock | int flags | const struct timespec __user *rqtp | struct timespec __user *rmtp |  | kernel/posix-timers.c
268 | sys_statfs64 | (const char __user *path, size_t sz, struct statfs64 __user *buf) | 0x10c | const char __user *path | size_t sz | struct statfs64 __user *buf |  |  | fs/statfs.c
269 | sys_fstatfs64 | (unsigned int fd, size_t sz, struct statfs64 __user *buf) | 0x10d | unsigned int fd | size_t sz | struct statfs64 __user *buf |  |  | fs/statfs.c
270 | sys_tgkill | (int tgid, int pid, int sig) | 0x10e | int tgid | int pid | int sig |  |  | kernel/signal.c
271 | sys_utimes | (char __user *filename, struct timeval __user *utimes) | 0x10f | char __user *filename | struct timeval __user *utimes |  |  |  | fs/utimes.c
272 | sys_fadvise64_64 | (int fd, loff_t offset, loff_t len, int advice) | 0x110 | int fd | loff_t offset | loff_t len | int advice |  | not found
273 | not implemented |  | 0x111 |  |  |  |  |  | 
274 | sys_mbind | (unsigned long start, unsigned long len, unsigned long mode, unsigned long __user *nmask, unsigned long maxnode, unsigned flags) | 0x112 |  |  |  |  |  | mm/mempolicy.c
275 | sys_get_mempolicy | (int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags) | 0x113 | int __user *policy | unsigned long __user *nmask | unsigned long maxnode | unsigned long addr | unsigned long flags | mm/mempolicy.c
276 | sys_set_mempolicy | (int mode, unsigned long __user *nmask, unsigned long maxnode) | 0x114 | int mode | unsigned long __user *nmask | unsigned long maxnode |  |  | mm/mempolicy.c
277 | sys_mq_open | (const char __user *name, int oflag, mode_t mode, struct mq_attr __user *attr) | 0x115 | const char __user *name | int oflag | mode_t mode | struct mq_attr __user *attr |  | ipc/mqueue.c
278 | sys_mq_unlink | (const char __user *name) | 0x116 | const char __user *name |  |  |  |  | ipc/mqueue.c
279 | sys_mq_timedsend | (mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout) | 0x117 | mqd_t mqdes | const char __user *msg_ptr | size_t msg_len | unsigned int msg_prio | const struct timespec __user *abs_timeout | ipc/mqueue.c
280 | sys_mq_timedreceive | (mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout) | 0x118 | mqd_t mqdes | char __user *msg_ptr | size_t msg_len | unsigned int __user *msg_prio | const struct timespec __user *abs_timeout | ipc/mqueue.c
281 | sys_mq_notify | (mqd_t mqdes, const struct sigevent __user *notification) | 0x119 | mqd_t mqdes | const struct sigevent __user *notification |  |  |  | ipc/mqueue.c
282 | sys_mq_getsetattr | (mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat) | 0x11a | mqd_t mqdes | const struct mq_attr __user *mqstat | struct mq_attr __user *omqstat |  |  | ipc/mqueue.c
283 | sys_kexec_load | (unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags) | 0x11b | unsigned long entry | unsigned long nr_segments | struct kexec_segment __user *segments | unsigned long flags |  | kernel/kexec.c
284 | sys_waitid | (int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru) | 0x11c | int which | pid_t pid | struct siginfo __user *infop | int options | struct rusage __user *ru | kernel/exit.c
285 | not implemented |  | 0x11d |  |  |  |  |  | 
286 | sys_add_key | (const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid) | 0x11e | const char __user *_type | const char __user *_description | const void __user *_payload | size_t plen | key_serial_t destringid | security/keys/keyctl.c
287 | sys_request_key | (const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid) | 0x11f | const char __user *_type | const char __user *_description | const char __user *_callout_info | key_serial_t destringid |  | security/keys/keyctl.c
288 | sys_keyctl | (int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) | 0x120 | int cmd | unsigned long arg2 | unsigned long arg3 | unsigned long arg4 | unsigned long arg5 | security/keys/keyctl.c
289 | sys_ioprio_set | (int which, int who, int ioprio) | 0x121 | int which | int who | int ioprio |  |  | fs/ioprio.c
290 | sys_ioprio_get | (int which, int who) | 0x122 | int which | int who |  |  |  | fs/ioprio.c
291 | sys_inotify_init | (void) | 0x123 |  |  |  |  |  | fs/notify/inotify/inotify_user.c
292 | sys_inotify_add_watch | (int fd, const char __user *path, u32 mask) | 0x124 | int fd | const char __user *path | u32 mask |  |  | fs/notify/inotify/inotify_user.c
293 | sys_inotify_rm_watch | (int fd, __s32 wd) | 0x125 | int fd | __s32 wd |  |  |  | fs/notify/inotify/inotify_user.c
294 | sys_migrate_pages | (pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to) | 0x126 | pid_t pid | unsigned long maxnode | const unsigned long __user *from | const unsigned long __user *to |  | mm/mempolicy.c
295 | sys_openat | (int dfd, const char __user *filename, int flags, int mode) | 0x127 | int dfd | const char __user *filename | int flags | int mode |  | fs/open.c
296 | sys_mkdirat | (int dfd, const char __user * pathname, int mode) | 0x128 | int dfd | const char __user * pathname | int mode |  |  | fs/namei.c
297 | sys_mknodat | (int dfd, const char __user * filename, int mode, unsigned dev) | 0x129 | int dfd | const char __user * filename | int mode | unsigned dev |  | fs/namei.c
298 | sys_fchownat | (int dfd, const char __user *filename, uid_t user, gid_t group, int flag) | 0x12a | int dfd | const char __user *filename | uid_t user | gid_t group | int flag | fs/open.c
299 | sys_futimesat | (int dfd, char __user *filename, struct timeval __user *utimes) | 0x12b | int dfd | char __user *filename | struct timeval __user *utimes |  |  | fs/utimes.c
300 | sys_fstatat64 | (int dfd, char __user *filename, struct stat64 __user *statbuf, int flag) | 0x12c | int dfd | char __user *filename | struct stat64 __user *statbuf | int flag |  | fs/stat.c
301 | sys_unlinkat | (int dfd, const char __user * pathname, int flag) | 0x12d | int dfd | const char __user * pathname | int flag |  |  | fs/namei.c
302 | sys_renameat | (int olddfd, const char __user * oldname, int newdfd, const char __user * newname) | 0x12e | int olddfd | const char __user * oldname | int newdfd | const char __user * newname |  | fs/namei.c
303 | sys_linkat | (int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags) | 0x12f | int olddfd | const char __user *oldname | int newdfd | const char __user *newname | int flags | fs/namei.c
304 | sys_symlinkat | (const char __user * oldname, int newdfd, const char __user * newname) | 0x130 | const char __user * oldname | int newdfd | const char __user * newname |  |  | fs/namei.c
305 | sys_readlinkat | (int dfd, const char __user *path, char __user *buf, int bufsiz) | 0x131 | int dfd | const char __user *path | char __user *buf | int bufsiz |  | fs/stat.c
306 | sys_fchmodat | (int dfd, const char __user * filename, mode_t mode) | 0x132 | int dfd | const char __user * filename | mode_t mode |  |  | fs/open.c
307 | sys_faccessat | (int dfd, const char __user *filename, int mode) | 0x133 | int dfd | const char __user *filename | int mode |  |  | fs/open.c
308 | sys_pselect6 | (int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig) | 0x134 |  |  |  |  |  | fs/select.c
309 | sys_ppoll | (struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize) | 0x135 | struct pollfd __user *ufds | unsigned int nfds | struct timespec __user *tsp | const sigset_t __user *sigmask | size_t sigsetsize | fs/select.c
310 | sys_unshare | (unsigned long unshare_flags) | 0x136 | unsigned long unshare_flags |  |  |  |  | kernel/fork.c
311 | sys_set_robust_list | (struct robust_list_head __user *head, size_t len) | 0x137 | struct robust_list_head __user *head | size_t len |  |  |  | kernel/futex.c
312 | sys_get_robust_list | (int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr) | 0x138 | int pid | struct robust_list_head __user * __user *head_ptr | size_t __user *len_ptr |  |  | kernel/futex.c
313 | sys_splice | (int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) | 0x139 |  |  |  |  |  | fs/splice.c
314 | sys_sync_file_range | (int fd, loff_t offset, loff_t nbytes, unsigned int flags) | 0x13a | int fd | loff_t offset | loff_t nbytes | unsigned int flags |  | not found
315 | sys_tee | (int fdin, int fdout, size_t len, unsigned int flags) | 0x13b | int fdin | int fdout | size_t len | unsigned int flags |  | fs/splice.c
316 | sys_vmsplice | (int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags) | 0x13c | int fd | const struct iovec __user *iov | unsigned long nr_segs | unsigned int flags |  | fs/splice.c
317 | sys_move_pages | (pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags) | 0x13d |  |  |  |  |  | mm/migrate.c
318 | sys_getcpu | (unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache) | 0x13e | unsigned __user *cpu | unsigned __user *node | struct getcpu_cache __user *cache |  |  | kernel/sys.c
319 | sys_epoll_pwait | (int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize) | 0x13f |  |  |  |  |  | fs/eventpoll.c
320 | sys_utimensat | (int dfd, char __user *filename, struct timespec __user *utimes, int flags) | 0x140 | int dfd | char __user *filename | struct timespec __user *utimes | int flags |  | fs/utimes.c
321 | sys_signalfd | (int ufd, sigset_t __user *user_mask, size_t sizemask) | 0x141 | int ufd | sigset_t __user *user_mask | size_t sizemask |  |  | fs/signalfd.c
322 | sys_timerfd_create | (int clockid, int flags) | 0x142 | int clockid | int flags |  |  |  | fs/timerfd.c
323 | sys_eventfd | (unsigned int count) | 0x143 | unsigned int count |  |  |  |  | fs/eventfd.c
324 | sys_fallocate | (int fd, int mode, loff_t offset, loff_t len) | 0x144 | int fd | int mode | loff_t offset | loff_t len |  | not found
325 | sys_timerfd_settime | (int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr) | 0x145 | int ufd | int flags | const struct itimerspec __user *utmr | struct itimerspec __user *otmr |  | fs/timerfd.c
326 | sys_timerfd_gettime | (int ufd, struct itimerspec __user *otmr) | 0x146 | int ufd | struct itimerspec __user *otmr |  |  |  | fs/timerfd.c
327 | sys_signalfd4 | (int ufd, sigset_t __user *user_mask, size_t sizemask, int flags) | 0x147 | int ufd | sigset_t __user *user_mask | size_t sizemask | int flags |  | fs/signalfd.c
328 | sys_eventfd2 | (unsigned int count, int flags) | 0x148 | unsigned int count | int flags |  |  |  | fs/eventfd.c
329 | sys_epoll_create1 | (int flags) | 0x149 | int flags |  |  |  |  | fs/eventpoll.c
330 | sys_dup3 | (unsigned int oldfd, unsigned int newfd, int flags) | 0x14a | unsigned int oldfd | unsigned int newfd | int flags |  |  | fs/fcntl.c
331 | sys_pipe2 | (int __user *fildes, int flags) | 0x14b | int __user *fildes | int flags |  |  |  | fs/pipe.c
332 | sys_inotify_init1 | (int flags) | 0x14c | int flags |  |  |  |  | fs/notify/inotify/inotify_user.c
333 | sys_preadv | (unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h) | 0x14d | unsigned long fd | const struct iovec __user *vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | fs/read_write.c
334 | sys_pwritev | (unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h) | 0x14e | unsigned long fd | const struct iovec __user *vec | unsigned long vlen | unsigned long pos_l | unsigned long pos_h | fs/read_write.c
335 | sys_rt_tgsigqueueinfo | (pid_t tgid, pid_t pid, int sig, siginfo_t __user *uinfo) | 0x14f | pid_t tgid | pid_t pid | int sig | siginfo_t __user *uinfo |  | kernel/signal.c
336 | sys_perf_event_open | ( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags) | 0x150 | struct perf_event_attr __user *attr_uptr | pid_t pid | int cpu | int group_fd | unsigned long flags | kernel/perf_event.c
337 | sys_recvmmsg | (int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout) | 0x151 | int fd | struct mmsghdr __user *msg | unsigned int vlen | unsigned flags | struct timespec __user *timeout | net/socket.c
