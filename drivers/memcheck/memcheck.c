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
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for testing virtual memory window");
MODULE_VERSION("0.1");

static char *remapped;
static struct page** pages;
#define MEM_SIZE (64*1024*1024)

struct vmap_area *find_vmap_area(unsigned long addr);

static int __init memcheck_init(void){
   unsigned long npages;
   int nid;
   int i;
   npages =  MEM_SIZE/PAGE_SIZE;

   pages = vmalloc(npages * sizeof(struct page *));
   for(i=0;i<npages;i++){
      pages[i] = alloc_pages(GFP_KERNEL,0); /* Allocate 1 page */
   }

   nid = page_to_nid(pages[0]); // Remap on the same NUMA node.

   remapped = vm_map_ram(pages, npages, nid, PAGE_KERNEL);
   if(remapped != NULL){
      printk(KERN_INFO "vm_map_range() succeeded %p\n",remapped);
   }
   else{
      printk(KERN_INFO "vm_map_range() failed\n");
   }
   printk(KERN_INFO "memcheck module loaded.\n");
   printk(KERN_INFO "memory size: %d\n",MEM_SIZE);
   printk(KERN_INFO "npages: %ld\n",npages);
   printk(KERN_INFO "page size: %ld\n",PAGE_SIZE);

   return 0;

}

static void __exit memcheck_exit(void){
   printk(KERN_INFO "memcheck module unloaded.\n");
}

module_init(memcheck_init);
module_exit(memcheck_exit);
