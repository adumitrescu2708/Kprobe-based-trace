// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Alexandra Dumitrescu adumitrescu2708@stud.acs.upb.ro
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include "tracer.h"
#include <linux/kprobes.h>
#include <linux/miscdevice.h>

#define tracer_file	            "tracer"
#define tracer_file_permissions 0000
#define KMALLOC_FUNC            "__kmalloc"
#define KFREE_FUNC              "kfree"
#define SCHEDULE_FUNC           "schedule"
#define UP_FUNC                 "up"
#define DOWN_INTERRUPTIBLE_FUNC "down_interruptible"
#define MUTEX_LOCK_NESTED       "mutex_lock_nested"
#define MUTEX_UNLOCK            "mutex_unlock"
#define PROBES_NO               8
#define MESSAGE "PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n"
#define DO_EXIT_UNLOCK			"do_exit"
struct proc_dir_entry *proc_tracer_file;

enum ops {
	kmalloc_counts,
	kfree_counts,
	sched_counts,
	up_counts,
	down_counts,
	lock_counts,
	unlock_counts
};
/*
 * Process info list - For each process registered we will use a list
 * storing its corresponding info (counters for the called syscalls)
 * and size of allocated/deallocated memory. This info will be printed
 * in /proc/tracer file entry.
 */
struct process_info_node {
	pid_t pid;
	unsigned int kmalloc_calls_count;
	unsigned int kfree_calls_count;
	unsigned int sched_calls_count;
	unsigned int up_calls_count;
	unsigned int down_calls_count;
	unsigned int lock_calls_count;
	unsigned int unlock_calls_count;
	size_t alloced_memory_size;
	size_t dealloced_memory_size;
};

struct process_info_list {
	struct process_info_node *info;
	struct list_head list;
};

/*
 * Memory address list - For each kmalloc syscall we keep track using
 * this list of the resulted memory address and its associated size.
 */
struct mem_address_info_node {
	void *addr;
	size_t size;
	pid_t pid;
};

struct mem_address_list {
	struct mem_address_info_node *info;
	struct list_head list;
};

LIST_HEAD(process_list_head);
LIST_HEAD(mem_address_list_head);
DEFINE_RWLOCK(lock);
DEFINE_RWLOCK(address_list_lock);

/*
 * Printing method
 */
static int tracer_print(struct seq_file *m, void *v)
{
	struct process_info_list *curr;

	seq_puts(m, MESSAGE);
	read_lock(&lock);
	list_for_each_entry(curr, &process_list_head, list) {
		seq_printf(m, "%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
			curr->info->pid,
			curr->info->kmalloc_calls_count,
			curr->info->kfree_calls_count,
			curr->info->alloced_memory_size,
			curr->info->dealloced_memory_size,
			curr->info->sched_calls_count,
			curr->info->up_calls_count,
			curr->info->down_calls_count,
			curr->info->lock_calls_count,
			curr->info->unlock_calls_count
		);
	}
	read_unlock(&lock);
	return 0;
}

static int probe_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_print, NULL);
}

static const struct proc_ops r_pops = {
	.proc_open		= probe_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

/*
 * This method retrieves the corresponding size of the given address from
 * the list by searching for the memory address in the list.
 */
static size_t get_address_size(void *addr)
{
	struct mem_address_list *mem_address_node;
	size_t size = -1;

	read_lock(&address_list_lock);
	list_for_each_entry(mem_address_node, &mem_address_list_head, list) {
		if (mem_address_node->info->addr == addr) {
			size = mem_address_node->info->size;
			break;
		}
	}
	read_unlock(&address_list_lock);

	return size;
}

/*
 * This method is used creating and adding a new node of process info to
 * the list, it uses the pid given in the parameter and initializes the
 * counter fields to 0.
 */
static int add_process_info_node(unsigned long pid)
{
	struct process_info_list *process_info_node =  kcalloc(1, sizeof(*process_info_node), GFP_KERNEL);

	if (!process_info_node)
		return -ENOMEM;

	process_info_node->info = kcalloc(1, sizeof(struct process_info_node), GFP_KERNEL);
	if (!process_info_node->info)
		return -ENOMEM;

	process_info_node->info->pid = pid;

	write_lock(&lock);
	list_add(&process_info_node->list, &process_list_head);
	write_unlock(&lock);

	return 0;
}

/*
 * This method is used creating and adding a new node of memory corresponding
 * info to the list. It uses the memory address with the corresponding size
 * from the given parameters.
 */
static int add_mem_address_info_node(void *addr, size_t data, pid_t pid)
{
	struct mem_address_list *node = kcalloc(1, sizeof(*node), GFP_ATOMIC);

	if (!node)
		return -ENOMEM;

	node->info = kcalloc(1, sizeof(struct mem_address_info_node), GFP_ATOMIC);

	if (!node->info)
		return -ENOMEM;

	node->info->addr = addr;
	node->info->size = data;
	node->info->pid = pid;

	write_lock(&address_list_lock);
	list_add(&node->list, &mem_address_list_head);
	write_unlock(&address_list_lock);
	return 0;
}

/*
 * This method is used for returning the process_info_list corresponding
 * to the given pid from the list of processes info.
 */
static struct process_info_list *get_process_info_node(unsigned long pid)
{
	struct process_info_list *process_info_node = NULL;
	struct process_info_list *node = NULL;

	read_lock(&lock);
	list_for_each_entry(process_info_node, &process_list_head, list) {
		if (process_info_node->info->pid == pid) {
			node = process_info_node;
			break;
		}
	}
	read_unlock(&lock);
	return node;
}

/*
 * Remove memory allocated by a process when exiting
 */
static void remove_allocated_memory_for_process(pid_t pid)
{
	struct mem_address_list *mem_address_node;
	struct list_head *i, *tmp;

	write_lock(&address_list_lock);
	list_for_each_safe(i, tmp, &mem_address_list_head) {
		mem_address_node = list_entry(i, struct mem_address_list, list);
		if (mem_address_node->info->pid == current->pid) {
			list_del(i);
			kfree(mem_address_node->info);
			kfree(mem_address_node);
		}
	}
	write_unlock(&address_list_lock);
}

/*
 * This method removes and frees allocated memory used for the node
 * corresponding to the pid specified by the first argument from the
 * list of processes info.
 */
static int remove_process_info_node(unsigned long pid)
{
	struct list_head *i, *tmp;
	struct process_info_list *process_info_node;

	write_lock(&lock);
	list_for_each_safe(i, tmp, &process_list_head) {
		process_info_node = list_entry(i, struct process_info_list, list);
		if (process_info_node->info->pid == pid) {
			list_del(i);
			write_unlock(&lock);
			kfree(process_info_node->info);
			kfree(process_info_node);
			return 0;
		}
	}
	write_unlock(&lock);


	return -EINVAL;
}

/*
 * Ioctl handler for the character device.
 */
static long probe_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		ret = add_process_info_node(arg);
		break;
	case TRACER_REMOVE_PROCESS:
		remove_allocated_memory_for_process(current->pid);
		ret = remove_process_info_node(arg);
		break;
	default:
		return -EINVAL;
	}

	/* in case of error, return the error */
	if (ret < 0)
		return ret;

	return 0;
}

/*
 * This handler is used to retrieve the current process's info
 * within the list, if found, and increment its corresponding counter .
 */
static int handle_increment_func(enum ops increment_func)
{
	struct process_info_list *ple = get_process_info_node(current->pid);

	if (ple != NULL) {
		write_lock(&lock);
		switch (increment_func) {
		case sched_counts:
			ple->info->sched_calls_count++;
			break;
		case up_counts:
			ple->info->up_calls_count++;
			break;
		case kmalloc_counts:
			ple->info->kmalloc_calls_count++;
			break;
		case down_counts:
			ple->info->down_calls_count++;
			break;
		case lock_counts:
			ple->info->lock_calls_count++;
			break;
		case unlock_counts:
			ple->info->unlock_calls_count++;
			break;
		default:
			break;
		}
		write_unlock(&lock);
		return 0;
	}

	return -EINVAL;
}

/*
 * Handlers for simple syscalls. Simply increment the corresponding counter
 */
static int schedule_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return handle_increment_func(sched_counts);
}
NOKPROBE_SYMBOL(schedule_probe_handler);

static int up_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return handle_increment_func(up_counts);
}
NOKPROBE_SYMBOL(up_probe_handler);

static int down_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return handle_increment_func(down_counts);
}
NOKPROBE_SYMBOL(down_probe_handler);

static int mutex_lock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return handle_increment_func(lock_counts);
}
NOKPROBE_SYMBOL(mutex_lock_probe_handler);

static int mutex_unlock_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return handle_increment_func(unlock_counts);
}
NOKPROBE_SYMBOL(mutex_unlock_probe_handler);

/*
 * Entry handler for kmalloc syscall. It places the size parameter into
 * the data field for future use in the probe handler.
 */
static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	*(size_t *)ri->data = regs->ax;
	return 0;
}
NOKPROBE_SYMBOL(kmalloc_probe_entry_handler);

/*
 * When a process exits, remove all memory allocations allocated by it and
 * remove the corresponding process info node from list.
 */
static int exit_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	remove_allocated_memory_for_process(current->pid);
	return remove_process_info_node(current->pid);
}
NOKPROBE_SYMBOL(exit_probe_handler);

/*
 * Handler for kmalloc syscall. This handler takes the resulted allocated
 * memory address from ax register together with the size previously placed
 * in the given kretprobe_instance structure's data field and creates a new
 * node within the list of memory addresses.
 * It then searches the list of processes info for the current process info
 * and, if found, increments its kmalloc counter and the size of
 * the allocated memory.
 */
static int kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int addr = regs->ax, res;
	struct process_info_list *process_info_node = get_process_info_node(current->pid);

	if (process_info_node != NULL) {
		res = add_mem_address_info_node((void *)addr, *(size_t *)ri->data, current->pid);
		if (res < 0)
			return res;

		write_lock(&lock);
		process_info_node->info->alloced_memory_size += *(size_t *)ri->data;
		process_info_node->info->kmalloc_calls_count++;
		write_unlock(&lock);
		return 0;
	}

	return -EINVAL;
}
NOKPROBE_SYMBOL(kmalloc_probe_handler);
/*
 * This memory is used for removing the node in the list of memory
 * having the corresponding address given as parameter. It also
 * frees the allocated memory for the node.
 */
static void remove_memory_node(void *addr)
{
	struct mem_address_list *mem_address_node;
	struct list_head *i, *tmp;

	write_lock(&address_list_lock);
	list_for_each_safe(i, tmp, &mem_address_list_head) {
		mem_address_node = list_entry(i, struct mem_address_list, list);
		if (mem_address_node->info->addr == addr) {
			list_del(i);
			write_unlock(&address_list_lock);
			kfree(mem_address_node->info);
			kfree(mem_address_node);
			return;
		}
	}
	write_unlock(&address_list_lock);
}

/*
 * Handler for kfree syscall. By getting the address parameter found in ax
 * register and searching in the memory lists for the entry, we retrieve
 * the corresponding size and increment the size of deallocated memory for
 * the current process. We also increment its kfree calls counter.
 * In the end we remove the memory entry in the list.
 */
static int kfree_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct process_info_list *procces_info_node;
	void *addr = (void *) regs->ax;
	size_t size = get_address_size(addr);

	procces_info_node = get_process_info_node(current->pid);

	if (procces_info_node != NULL) {
		write_lock(&lock);
		procces_info_node->info->dealloced_memory_size += size;
		procces_info_node->info->kfree_calls_count++;
		write_unlock(&lock);

		remove_memory_node(addr);
		return 0;
	}

	return -EINVAL;
}
NOKPROBE_SYMBOL(kfree_probe_handler);

const struct file_operations fops = {
	.unlocked_ioctl     = probe_ioctl
};

static struct miscdevice tracer_device = {
	.minor = TRACER_DEV_MINOR,
	.name = "tracer",
	.fops = &fops
};

static struct kretprobe _kmalloc_probe = {
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_handler,
	.maxactive = 60,
	.kp = {.symbol_name = KMALLOC_FUNC}
};

static struct kretprobe _kfree_probe = {
	.entry_handler = kfree_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = KFREE_FUNC}
};

static struct kretprobe _schedule_probe = {
	.entry_handler = schedule_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = SCHEDULE_FUNC}
};

static struct kretprobe _up_probe = {
	.entry_handler = up_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = UP_FUNC}
};

static struct kretprobe _down_probe = {
	.entry_handler = down_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = DOWN_INTERRUPTIBLE_FUNC}
};

static struct kretprobe _lock_probe = {
	.entry_handler = mutex_lock_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = MUTEX_LOCK_NESTED}
};

static struct kretprobe _unlock_probe = {
	.entry_handler = mutex_unlock_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = MUTEX_UNLOCK}
};

static struct kretprobe _exit_probe = {
	.entry_handler = exit_probe_handler,
	.maxactive = 32,
	.kp = {.symbol_name = DO_EXIT_UNLOCK}
};

static struct kretprobe probes[PROBES_NO + 1];

/*
 * Init method for the kernel module - creates a /proc file entry called
 * tracer and registers the kretprobes handlers that are going to be used
 * for the 7 syscalls inspected.
 */
static void init_probes(void)
{
	int i = 0;

	probes[i++] = _kmalloc_probe;
	probes[i++] = _kfree_probe;
	probes[i++] = _exit_probe;
	probes[i++] = _lock_probe;
	probes[i++] = _unlock_probe;
	probes[i++] = _up_probe;
	probes[i++] = _down_probe;
	probes[i++] = _schedule_probe;
}

static int probe_init(void)
{
	int ret, i;

	proc_tracer_file = proc_create(tracer_file, tracer_file_permissions, NULL, &r_pops);
	if (!proc_tracer_file)
		goto proc_cleanup;

	init_probes();

	for (i = 0; i < PROBES_NO; i++) {
		ret = register_kretprobe(&probes[i]);
		if (ret < 0)
			goto kreprobes_cleanup;
	}

	ret = misc_register(&tracer_device);

	if (ret < 0)
		return ret;

	return 0;

kreprobes_cleanup:
	for (i = 0; i < PROBES_NO; i++)
		unregister_kretprobe(&probes[i]);

proc_cleanup:
	proc_remove(proc_tracer_file);
	return -ENOMEM;
}

/*
 * Method used for freeing the memory allocated for the lists on kernel cleanup
 * function
 */
static void destroy_lists(void)
{
	struct list_head *i, *n;
	struct process_info_list   *process_info_node;
	struct mem_address_list    *mem_address_list_node;

	write_lock(&lock);
	list_for_each_safe(i, n, &process_list_head) {
		process_info_node = list_entry(i, struct process_info_list, list);
		list_del(i);
		kfree(process_info_node->info);
		kfree(process_info_node);
	}
	write_unlock(&lock);

	write_lock(&address_list_lock);
	list_for_each_safe(i, n, &mem_address_list_head) {
		mem_address_list_node = list_entry(i, struct mem_address_list, list);
		list_del(i);
		kfree(mem_address_list_node->info);
		kfree(mem_address_list_node);
	}
	write_unlock(&address_list_lock);
}

/*
 * Exit function - used for removing the probes used, freeing the memory
 * used within the lists, removing the file entry in /proc and deregister
 * the character device.
 */
static void probe_exit(void)
{
	int i;

	for (i = 0; i < PROBES_NO; i++)
		unregister_kretprobe(&probes[i]);

	destroy_lists();

	misc_deregister(&tracer_device);
	proc_remove(proc_tracer_file);
}

module_init(probe_init);
module_exit(probe_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Alexandra Dumitrescu adumitrescu2708@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");
