#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    pid_t pid;
    int status;
    pid = fork();

    if (pid == 0)
    {
        execlp("ls", "ls", "-l", ".", (char *)0);
    }

    waitpid(pid, &status, 0);

    return 0;
}