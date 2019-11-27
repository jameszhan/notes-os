
列出文件或目录对应的 `inode` 

```bash
ls -i *
ls -il *
ls -ild *
```

## mount 


```bash
mkdir test1 test2

ls -ild test1 test2
# 23075692 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test1
# 23075693 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test2
```

```bash
sudo sh -c su root

mount --bind test1 test2
ls -ild test1 test2
# 23075692 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test1
# 23075692 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test2

umount test2
# 23075692 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test1
# 23075693 drwxr-xr-x 2 hscode sudo 4096 Sep 19 10:31 test2
```

### mount bind 与 hard link

`mount --bind` 命令是将前一个目录挂载到后一个目录上，所有对后一个目录的访问其实都是对前一个目录的访问。

看起来，mount --bind命令和硬连接很像，都是连接到同一个inode上面，只不过hard link无法连接目录，而mount --bind命令弥补了这个缺陷。
但两者的执行原理是不一样的。

当 `mount --bind` 命令执行后，`Linux` 将会把被挂载目录的目录项（也就是该目录文件的 `block`，记录了下级目录的信息）屏蔽，在本例里就是 test2 的下级路径被隐藏起来了（注意，只是隐藏不是删除，数据都没有改变，只是访问不到了）

同时，内核将挂载目录（本例里是 test1）的目录项记录在内存里的一个 `s_root` 对象里

在 `mount` 命令执行时，`VFS` 会创建一个 `vfsmount` 对象，这个对象里包含了整个文件系统所有的 `mount` 信息，
其中也会包括本次 `mount` 中的信息，这个对象是一个 `HASH` 值对应表（`HASH`值通过对路径字符串的计算得来），表里就有 test1 到 test2 两个目录的HASH值对应关系

命令执行完后，当访问 `test2` 下的文件时，系统会告知 `test2` 的目录项被屏蔽掉了，自动转到内存里找 `VFS`，通过 `vfsmount` 了解到 test2 和 test1 的对应关系，从而读取到 test1 的inode，这样在 test2 下读到的全是 test1 目录下的文件

由上述过程可知，mount --bind 和硬连接的重要区别有：

1. `mount --bind` 连接的两个目录的 `inode` 号码并不一样，只是被挂载目录的 `block` 被屏蔽掉，`inode` 被重定向到挂载目录的 `inode`（被挂载目录的 `inode` 和 `block` 依然没变）
2. 两个目录的对应关系存在于内存里，一旦重启挂载关系就不存在了


### 利用 mount bind 进行安全修改

```bash
sudo sh -c su root

cp -a /etc /tmp
mount -o bind /tmp/etc /etc

echo "127.0.0.1 localserver" >> /etc/hosts
ls -idl /etc/hosts /tmp/etc/hosts
# 25562141 -rw-r--r-- 1 root root 209 Sep 19 11:09 /etc/hosts
# 25562141 -rw-r--r-- 1 root root 209 Sep 19 11:09 /tmp/etc/hosts

umount /etc

ls -idl /etc/hosts /tmp/etc/hosts
# 10748248 -rw-r--r-- 1 root root 187 May 14 15:25 /etc/hosts
# 25562141 -rw-r--r-- 1 root root 209 Sep 19 11:09 /tmp/etc/hosts
```



