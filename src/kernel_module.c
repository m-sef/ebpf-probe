#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

int init_module(void)
{
    printk(KERN_INFO "Hello everynyan~\n");

    return 0;
}

int cleanup_module(void)
{
    printk(KERN_INFO "Goodbye everynyan~\n");
}