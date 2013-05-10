#TOYKIT -- a toy Linux rootkit
Use at your own risk, dangerous code.

##USAGE
###DYNAMIC COMMANDS (after module load time)
kill -31 12345 gives root access
kill -16 [some inode] hides a file with inode some inode

###STATIC COMMANDS (before module load time)
process hiding -- HIDE PROC will not be visible to user
port hiding -- HIDE PORT will not be visible to user

###STEALTH MODE 
rootkit is invisible and unremovable
