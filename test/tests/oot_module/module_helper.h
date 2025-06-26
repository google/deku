#ifndef MY_MODULE_HELPER_H
#define MY_MODULE_HELPER_H

void helper_print_init_message(const char *module_name);
void helper_print_message(const char *message);
int helper_calculate(int x);
ssize_t helper_proc_read(char __user *usr_buf, size_t count, loff_t *pos, int param_value);

#endif