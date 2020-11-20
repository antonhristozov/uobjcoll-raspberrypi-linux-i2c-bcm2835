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
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for testing virtual memory window");
MODULE_VERSION("0.1");

static char *remapped;
static struct page** pages;
static unsigned long npages;
#define MEM_SIZE (64*1024*1024)

// Other defines we need
#define VMAP_MAX_ALLOC          BITS_PER_LONG   /* 256K with 4K pages */
// Supplementary funct

int vmap_page_range(unsigned long start, unsigned long end,
                           pgprot_t prot, struct page **pages);

struct vmap_area *alloc_vmap_area(unsigned long size,       
                                unsigned long align,
                                unsigned long vstart, unsigned long vend,
                                int node, gfp_t gfp_mask);

void *vb_alloc(unsigned long size, gfp_t gfp_mask);

void *vm_map_ram_virt_hole(struct page **pages, unsigned int count, int node, pgprot_t prot)
{
        unsigned long size = count << PAGE_SHIFT;
        unsigned long addr;
        void *mem;
	addr = 0xfae00000; 
	mem = (void *)addr;
	size = MEM_SIZE;
        if (vmap_page_range(addr, addr + size, prot, pages) < 0) {
                vm_unmap_ram(mem, count);
                return NULL;
        }
        return mem;
}


static int __init memcheck_init(void){
   int nid;
   int i;
   npages =  MEM_SIZE/PAGE_SIZE;

   pages = vmalloc(npages * sizeof(struct page *));
   for(i=0;i<npages;i++){
      pages[i] = alloc_pages(GFP_KERNEL,0); /* Allocate 1 page */
   }


   nid = page_to_nid(pages[0]); // Remap on the same NUMA node.

   remapped = (char *) vm_map_ram_virt_hole(pages, npages, nid, PAGE_KERNEL);
   if(remapped != NULL){
      printk(KERN_INFO "vm_map_range() succeeded %p\n",remapped);
   }
   else{
      printk(KERN_INFO "vm_map_range() failed\n");
   }
   /* Let's prove that it is contiguous by going to the end of the space linearly */
   printk(KERN_INFO "memory address start %p\n",remapped);
   printk(KERN_INFO "memory address end minus 13 %p\n",remapped+MEM_SIZE-13);
   memcpy(remapped,"memcheck_start\0",15);
   memcpy(remapped+MEM_SIZE-13,"memcheck_end\0",13);
   printk(KERN_INFO "memcheck module loaded.\n");
   printk(KERN_INFO "memory contents remapped:  %s\n",remapped);
   printk(KERN_INFO "memory contents remapped end minus 13:  %s\n",remapped+MEM_SIZE-13);
   printk(KERN_INFO "memory size: %d\n",MEM_SIZE);
   printk(KERN_INFO "npages: %ld\n",npages);
   printk(KERN_INFO "page size: %ld\n",PAGE_SIZE);

   return 0;

}

static void __exit memcheck_exit(void){
   int i;
   for(i=0;i<npages;i++){
      page_cache_release(pages[i]); /* Deallocate each page */
   }

   printk(KERN_INFO "memcheck module unloaded.\n");
}

module_init(memcheck_init);
module_exit(memcheck_exit);
