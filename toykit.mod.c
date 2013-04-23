#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x98397cc5, "module_layout" },
	{ 0x7fe4fb6a, "pv_cpu_ops" },
	{ 0x156b0a42, "kmem_cache_alloc_trace" },
	{ 0x992847d2, "kmalloc_caches" },
	{ 0x5f5602c6, "current_task" },
	{ 0x8235805b, "memmove" },
	{ 0x37a0cba, "kfree" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x50eedeb8, "printk" },
	{ 0xb4390f9a, "mcount" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EC3F9608A9DFC26B10E4688");
