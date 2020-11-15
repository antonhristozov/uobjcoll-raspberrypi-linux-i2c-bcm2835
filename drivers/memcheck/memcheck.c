#include <linux/init.h>  
#include <linux/kernel.h> 
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <asm/stat.h>
#include <asm/types.h>
#include <asm/fcntl.h>
#include <linux/io.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for testing virtual memory window");
MODULE_VERSION("0.1");

#define MEM_SIZE  1024
static char *buf;
static char *virt_buf;

static int __init memcheck_init(void){
   printk(KERN_INFO "memcheck module loaded.\n");
   buf = kmalloc(MEM_SIZE,GFP_KERNEL); /* get 16384 bytes of physical memory */
   if (!buf){
      printk("memcheck kmalloc() failed\n");
   }else{
      printk("memcheck kmalloc() succeeded at: %p\n", buf);
   }
   strcpy(buf,"memcheck123"); 

   virt_buf = NULL;
   //virt_buf = (char *)ioremap_page_range(0,MEM_SIZE,(unsigned long)buf,PAGE_SHARED);
   if(!virt_buf){
      printk("memcheck remapping failed \n");
   }
   else{
      printk("memcheck remapping succeeded at: %p\n", virt_buf);
   }
   return 0;
}

static void __exit memcheck_exit(void){
   printk("buf contents: %s\n",buf);
   kfree(buf);
   printk(KERN_INFO "memcheck module unloaded.\n");
}

module_init(memcheck_init);
module_exit(memcheck_exit);
