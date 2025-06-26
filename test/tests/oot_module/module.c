#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#include "module_helper.h"

#define MODULE_NAME "deku_test_module"
#define PROC_FILE_NAME "deku_test"

static struct proc_dir_entry *proc_entry;

static ssize_t proc_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	return helper_proc_read(buf, count, pos, 0);
}

static const struct proc_ops proc_fops = {
	.proc_read = proc_read,
};

static int __init test_module_init(void)
{
	proc_entry = proc_create(PROC_FILE_NAME, 0444, NULL, &proc_fops);
	if (!proc_entry) {
		printk(KERN_ERR "%s: Failed to create proc entry\n", MODULE_NAME);
		return -ENOMEM;
	}

	helper_print_init_message("Module loaded successfully");

	return 0;
}

static void __exit test_module_exit(void)
{
	if (proc_entry) {
		proc_remove(proc_entry);
	}

	helper_print_message("Module unloading");
}

module_init(test_module_init);
module_exit(test_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marek Maslanka");
MODULE_DESCRIPTION("DEKU test module");