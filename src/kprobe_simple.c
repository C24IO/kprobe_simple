/* 
 * kprobe_simple.c.c
 * Copyright (C) 2013 Chaitanya H. <C@24.IO>
 * Version 1.0: Tue Feb 12 09:40:58 PST 2013
 * 
 * This file is a simple "Hello World" implementation of kprobe jprobe.
 * I am using it to study the Linux TCP/IP stack flow through the Linux kernel.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * 
 * Code from: http://www.linuxforu.com/2011/04/kernel-debugging-using-kprobe-and-jprobe/
 * Machine: 3.2.0-37-generic
 *
 */

#include<linux/module.h> 
#include<linux/version.h> 
#include<linux/kernel.h> 
#include<linux/init.h> 
#include<linux/kprobes.h> 
#include<net/ip.h> 
 
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Chaitanya H <C@24.IO>");
MODULE_DESCRIPTION("Hello World implementation of kprobe jprobe");
MODULE_ALIAS("kprobe_simple");

//Bringing this back just so that this can compile and I can see things. 

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIPQUAD_FMT "%u.%u.%u.%u"

static struct kprobe kp = {
	.symbol_name = "ip_rcv",
}; 

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx,"
                        " flags = 0x%lx\n",
                p->addr, regs->ip, regs->flags);

        /* A dump_stack() here will give a stack backtrace */

	//dump_stack(); //above is proven :-) 

        return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
                                unsigned long flags)
{
        printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n",
                p->addr, regs->flags);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
        printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
                p->addr, trapnr);
        /* Return 0 because we don't handle the fault. */
        return 0;
}
 
static int __init myinit(void) 
{ 

    int ret;

    printk("module inserted\n "); 

    //my_probe.kp.addr = (kprobe_opcode_t *)0xffffffff81570830; //cat /proc/kallsyms | grep ip_rcv gets you ffffffff8156b770 T ip_rcv

    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
    	printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
    	return ret;
    }

    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    return 0; 
} 
 
static void __exit myexit(void) 
{ 
    unregister_kprobe(&kp); 

    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);

    printk("module removed\n "); 
} 
 
 
module_init(myinit); 
module_exit(myexit); 

