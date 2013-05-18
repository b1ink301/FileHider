### README ###

Sample Mac OS X kernel extension that demonstrates how to hide files by
hijacking _getdirentries\*_ syscalls. The kext resolves *\_nsysent* from the
kernel image in memory and brute forces it's way to *_sysent* in a very dirty
fashion...
Ah well, this shit is supposed to run on Mountain Lion (10.8.3), 64-bits.


####Bugz/ToDo:####

*	restoring the original syscalls on unload causes a kernel panic (wtf?!)
*	come up w/ a better way of brute forcing sysent!
*	block file from direct lookups (hijack open, stat, lstat)

