#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int count = 0;
    printf("Before fork count: %d, pid: %d\n", count, getpid());

    if (vfork())
    {
        count += 2;
        printf("Parent After fork count: %d, pid: %d\n", count, getpid());
    }
    else
    {
        count += 3;
        printf("Child After fork count: %d, pid: %d\n", count, getpid());
    }
    exit(0);
//    return 0;
}