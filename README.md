#Toykit -- a toy Linux rootkit
Use at your own risk, dangerous code.

#Usage
##Dynamic Commands 
Commands that can be run after module load time:
1. kill -31 12345 gives root access.
2. kill -16 [some inode] hides a file with inode some inode.

##Static Commands 
Commands that have to be set before module load time:
1. Process hiding, HIDE PROC will not be visible to user.
2. Port hiding, HIDE PORT will not be visible to user.

##Stealth Mode 
Rootkit is invisible and unremovable.
Comment out STEALTH MODE to turn off.
