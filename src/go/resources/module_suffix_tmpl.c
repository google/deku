/*
 * Copyright (c) 2024 Google LLC All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

static int deku_init(void)
{
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	ret = klp_enable_patch(&deku_patch);
		return ret;
#else
	ret = klp_register_patch(&deku_patch);
	if (ret)
		return ret;
	ret = klp_enable_patch(&deku_patch);
	if (ret) {
		WARN_ON(klp_unregister_patch(&deku_patch));
		return ret;
	}
	return 0;
#endif
}

static void deku_exit(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 11, 0)
	klp_disable_patch(&deku_patch);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	WARN_ON(klp_unregister_patch(&deku_patch));
#endif
}

module_init(deku_init);
module_exit(deku_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
