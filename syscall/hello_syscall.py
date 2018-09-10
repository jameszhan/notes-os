
# http://man7.org/linux/man-pages/dir_section_2.html

import ctypes

libc = ctypes.CDLL(None)
syscall = libc.syscall

print(syscall(39))

