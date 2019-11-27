#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>

#define CHILD_STACK 1024

int count = 0;

int child_process(void *args)
{
    count += 3;
    printf("Child After fork count: %d, pid: %d\n", count, getpid());
    return 0;
}

int main(int argc, char *argv[])
{
    int pid, status;
    void *child_stack = malloc(CHILD_STACK);

    printf("Before fork count: %d, pid: %d\n", count, getpid());

    if (!child_stack)
    {
        fprintf(stderr, "Failed to allocate child stack\n");
        exit(1);
    }

    pid = clone(child_process,
                (void*)((char*)child_stack + CHILD_STACK),
                CLONE_VM | CLONE_VFORK,
                0);

    if (pid == -1)
    {
        perror("Clone failed: ");
        exit(2);
    }
    else
    {
        count += 2;
        waitpid(pid, &status, 0);
        printf("Child After fork count: %d, pid: %d\n", count, getpid());
    }
    return 0;
}