#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    int count = 0;
    printf("Before fork count: %d, pid: %d\n", count, getpid());

    if (fork())
    {
        count += 2;
        printf("Parent After fork count: %d, pid: %d\n", count, getpid());
    }
    else
    {
        count += 3;
        printf("Child After fork count: %d, pid: %d\n", count, getpid());
    }
    return 0;
}