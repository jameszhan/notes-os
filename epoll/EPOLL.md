

EPOLLIN
              The associated file is available for read(2) operations.
EPOLLOUT
              The associated file is available for write(2) operations.
EPOLLRDHUP
              Stream  socket peer closed connection, or shut down writing half
              of connection.  (This flag is especially useful for writing sim-
              ple code to detect peer shutdown when using Edge Triggered moni-
              toring.)
EPOLLPRI
              There is urgent data available for read(2) operations.
EPOLLERR
              Error condition happened  on  the  associated  file  descriptor.
              epoll_wait(2)  will always wait for this event; it is not neces-
              sary to set it in events.
EPOLLHUP
              Hang  up   happened   on   the   associated   file   descriptor.
              epoll_wait(2)  will always wait for this event; it is not neces-
              sary to set it in events.
EPOLLET
              Sets  the  Edge  Triggered  behavior  for  the  associated  file
              descriptor.   The default behavior for epoll is Level Triggered.
              See epoll(7) for more detailed information about Edge and  Level
              Triggered event distribution architectures.
EPOLLONESHOT (since Linux 2.6.2)
              Sets  the  one-shot behavior for the associated file descriptor.
              This means that after an event is pulled out with  epoll_wait(2)
              the  associated  file  descriptor  is internally disabled and no
              other events will be reported by the epoll interface.  The  user
              must  call  epoll_ctl() with EPOLL_CTL_MOD to re-enable the file
              descriptor with a new event mask.
