# Stat Usage

The stat utility displays information about the file pointed to by file.  Read, write or execute permissions of the named file are
not required, but all directories listed in the path name leading to the file must be searchable.  If no argument is given, stat
displays information about the file descriptor for standard input.

When invoked as readlink, only the target of the symbolic link is printed.  If the given argument is not a symbolic link, readlink
will print nothing and exit with an error.

```bash
ruby -e "p File.stat('notes-stat.md')"
#<File::Stat dev=0x1000004, ino=3862927, mode=0100644, nlink=1, uid=502, gid=20, rdev=0x0, size=1027, blksize=4096, blocks=8, atime=2019-01-21 11:20:17 +0800, mtime=2019-01-21 11:20:11 +0800, ctime=2019-01-21 11:20:11 +0800, birthtime=2019-01-21 11:03:46 +0800>
stat notes-stat.md
#16777220 3862927 -rw-r--r-- 1 james staff 0 1027 "Jan 21 11:21:01 2019" "Jan 21 11:21:01 2019" "Jan 21 11:21:01 2019" "Jan 21 11:03:46 2019" 4096 8 0 notes-stat.md
stat -s notes-stat.md
#st_dev=16777220 st_ino=3862927 st_mode=0100644 st_nlink=1 st_uid=502 st_gid=20 st_rdev=0 st_size=1047 st_atime=1548041201 st_mtime=1548041071 st_ctime=1548041071 st_birthtime=1548039826 st_blksize=4096 st_blocks=8 st_flags=0

python -c "import os;print(os.stat('notes-stat.md'))"
```

## 取出对应列

field | desc
--- | ---
d   | Device upon which file resides.
i   | file's inode number.
p   | File type and permissions.
l   | Number of hard links to file.
u, g| User ID and group ID of file's owner.
r   | Device number for character and block device special files.
a, m, c, B | The time file was last accessed or modified, of when the inode was last changed, or the birth time of the inode.
z   | The size of file in bytes.
b   | Number of blocks allocated for file.
k   | Optimal file system I/O operation block size.
f   | User defined flags for file.
v   | Inode generation number.
N   | The name of the file.
T   | The file type, either as in ls -F or in a more descriptive form if the sub field specifier H is given.
Y   | The target of a symbolic link.
Z   | Expands to ``major,minor'' from the rdev field for character or block special devices and gives size output for all others.

**文件大小**

```bash
stat -f%z notes-stat.md

stat -f '%z %N' notes-stat.md

git ls-files -z | xargs -0 stat -f '%z %N' | sort -n -r
```