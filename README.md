### README ###

Sample Mac OS X kernel extension that demonstrates how to hide files by
hijacking _getdirentries\*_ syscalls. The position of the syscall table
*_sysent* is gained by fG!'s method:
>	The kext looks up the address and size for the \_\_DATA segment of the
>	kernel image in memory. Next the location of *_sysent* is brute forced
>	by searching the \_\_DATA segment.

Ah well, this shit is supposed to run on Mountain Lion (10.8.3), 64-bits.


####Bugz/ToDo:####

*	block file from direct lookups (hijack open, stat, lstat)

