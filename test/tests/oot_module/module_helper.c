#include <linux/kernel.h>
#include <linux/uaccess.h>
#include "module_helper.h"

__always_inline void helper_print_init_message(const char *message)
{
	printk(KERN_INFO "INIT: %s\n", message);
}

void helper_print_message(const char *message)
{
	printk(KERN_INFO "MSG: %s\n", message);
}

int helper_calculate(int x)
{
	return x * 2;
}

ssize_t helper_proc_read(char __user *usr_buf, size_t count, loff_t *pos, int param_value)
{
	char buffer[64];
	size_t len;

	if (*pos > 0) {
		return 0;
	}

	len = snprintf(buffer, sizeof(buffer),
				  "DEKU test procfs. Param value: %d\n",
				  param_value);

	if (len > count) {
		return -EINVAL;
	}

	if (copy_to_user(usr_buf, buffer, len)) {
		return -EFAULT;
	}

	*pos += len;
	return len;
}
