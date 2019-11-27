import os
import sys

count = 0

print('Before fork count: {}, pid: {}.'.format(count, os.getpid()))
count += 1

child_pid = os.fork()
if child_pid == 0:
    count += 5
    print("Child After fork count: {}, pid: {}.".format(count, os.getpid()))
    sys.exit(os.EX_OK)
else:
    count += 3
    print("Parent After fork count: {}, pid: {}.".format(count, os.getpid()))
