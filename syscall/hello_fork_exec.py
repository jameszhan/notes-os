import os

count = 0

print('Before fork count: {}, pid: {}.'.format(count, os.getpid()))
count += 1

child_pid = os.fork()
if child_pid == 0:
    print("Child Before exec count: {}, pid: {}.".format(count, os.getpid()))
    count += 5
    os.execlp("echo", "echo", "Hello World")
    # The following line never execute
    print("Child After exec count: {}, pid: {}.".format(count, os.getpid()))
else:
    count += 3
    print("Parent After fork count: {}, pid: {}.".format(count, os.getpid()))
