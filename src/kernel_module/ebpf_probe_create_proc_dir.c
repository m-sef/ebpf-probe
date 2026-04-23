/**
 * @file ebpf_probe_create_proc_dir.c
 * @author Seth Moore (slmoore@hamilton.edu)
 * @brief 
 * 
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define LICENSE     "GPL"
#define AUTHOR      "Seth Moore (slmoore@hamilton.edu)"
#define DESCRIPTION "Create '/proc/ebpf_probe/' directory"
#define PROC_FILE_SYSTEM_DIRECTORY "ebpf_probe"

static struct proc_dir_entry* ebpf_probe_proc_directory;

static int __init ebpf_probe_init_module(void)
{
    printk(KERN_INFO "Hello everynyan~\n");

    return 0;
}

module_init(ebpf_probe_init_module);

static void __exit ebpf_probe_exit_module(void)
{
    printk(KERN_INFO "Goodbye everynyan~\n");
}

module_exit(ebpf_probe_exit_module);

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);