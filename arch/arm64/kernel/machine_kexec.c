// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/page-flags.h>
#include <linux/smp.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/page.h>

#include "cpu-reset.h"

/* Global variables for the arm64_relocate_new_kernel routine. */
extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned long arm64_relocate_new_kernel_size;
void* migration_threads;
void* phy_migration_threads;

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
	const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:%d:\n", func, line);
	pr_debug("  kexec kimage info:\n");
	pr_debug("    type:        %d\n", kimage->type);
	pr_debug("    start:       %lx\n", kimage->start);
	pr_debug("    head:        %lx\n", kimage->head);
	pr_debug("    nr_segments: %lu\n", kimage->nr_segments);
	pr_debug("    kern_reloc: %pa\n", &kimage->arch.kern_reloc);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("      segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);
	}
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	/* Empty routine needed to avoid build errors. */
}

int machine_kexec_post_load(struct kimage *kimage)
{
	void *reloc_code = page_to_virt(kimage->control_code_page);

	memcpy(reloc_code, arm64_relocate_new_kernel,
	       arm64_relocate_new_kernel_size);
	kimage->arch.kern_reloc = __pa(reloc_code);
	kexec_image_info(kimage);

	/* Flush the reloc_code in preparation for its execution. */
	__flush_dcache_area(reloc_code, arm64_relocate_new_kernel_size);
	flush_icache_range((uintptr_t)reloc_code, (uintptr_t)reloc_code +
			   arm64_relocate_new_kernel_size);

	return 0;
}

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 * Forbid loading a kexec kernel if we have no way of hotplugging cpus or cpus
 * are stuck in the kernel. This avoids a panic once we hit machine_kexec().
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	if (kimage->type != KEXEC_TYPE_CRASH && cpus_are_stuck_in_kernel()) {
		pr_err("Can't kexec: CPUs are stuck in the kernel.\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * kexec_list_flush - Helper to flush the kimage list and source pages to PoC.
 */
static void kexec_list_flush(struct kimage *kimage)
{
	kimage_entry_t *entry;

	for (entry = &kimage->head; ; entry++) {
		unsigned int flag;
		void *addr;

		/* flush the list entries. */
		__flush_dcache_area(entry, sizeof(kimage_entry_t));

		flag = *entry & IND_FLAGS;
		if (flag == IND_DONE)
			break;

		addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			/* Set entry point just before the new list page. */
			entry = (kimage_entry_t *)addr - 1;
			break;
		case IND_SOURCE:
			/* flush the source pages. */
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DESTINATION:
			break;
		default:
			BUG();
		}
	}
}

/**
 * kexec_segment_flush - Helper to flush the kimage segments to PoC.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:\n", __func__);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("  segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

		__flush_dcache_area(phys_to_virt(kimage->segment[i].mem),
			kimage->segment[i].memsz);
	}
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
	bool in_kexec_crash = (kimage == kexec_crash_image);
	bool stuck_cpus = cpus_are_stuck_in_kernel();

	/*
	 * New cpus may have become stuck_in_kernel after we loaded the image.
	 */
	BUG_ON(!in_kexec_crash && (stuck_cpus || (num_online_cpus() > 1)));
	WARN(in_kexec_crash && (stuck_cpus || smp_crash_stop_failed()),
		"Some CPUs may be stale, kdump will be unreliable.\n");

	/* Flush the kimage list and its buffers. */
	kexec_list_flush(kimage);

	/* Flush the new image if already in place. */
	if ((kimage != kexec_crash_image) && (kimage->head & IND_DONE))
		kexec_segment_flush(kimage);

	pr_info("Bye!\n");

	local_daif_mask();

	phys_addr_t src_phys_addr = virt_to_phys(((struct task_struct*)migration_threads)->stack); // Replace with actual source physical address
	//   fffffff
	// 230000000
	//   0000000
	// pr_info("migration_threads: %lx\n", ((struct task_struct*)migration_threads)->stack);
	// pr_info("src_phys_addr: %lx\n", src_phys_addr);
    phys_addr_t dst_phys_addr = 0x0000000230000000; // Replace with actual destination physical address
    size_t size = 16384; // Replace with the actual size you want to copy

    void *src_vaddr;
    void *dst_vaddr;

    // Map the physical addresses to kernel virtual addresses
    // src_vaddr = ioremap(src_phys_addr, size);
    // if (!src_vaddr) {
    //     pr_err("Failed to map source physical address\n");
    //     // return -ENOMEM;
    // }
	src_vaddr = (void*)((struct task_struct*)migration_threads)->stack;

    // dst_vaddr = ioremap(dst_phys_addr, size);
    // if (!dst_vaddr) {
    //     pr_err("Failed to map destination physical address\n");
    //     iounmap(src_vaddr);
    //     // return -ENOMEM;
    // }
	dst_vaddr = (void*)0xffff0000d9664000;
	// = kmalloc(size, GFP_KERNEL);
	// pr_info("dst_vaddr: %lx\n", dst_vaddr);

	phy_migration_threads = virt_to_phys(dst_vaddr);
	// pr_info("phy_migration_threads: %lx\n", phy_migration_threads);

    // Copy the content from the source to the destination
    memcpy(dst_vaddr, src_vaddr, size);

	dst_vaddr = (void*)0xffff0000d9669000;
	// = kmalloc(size, GFP_KERNEL);
	size = 104;
	// pr_info("dst_vaddr: %lx\n", dst_vaddr);

	phy_migration_threads = virt_to_phys(dst_vaddr);
	src_vaddr = (void*)&((struct task_struct*)migration_threads)->thread.cpu_context;
	// pr_info("phy_migration_threads: %lx\n", src_vaddr);

    // Copy the content from the source to the destination
    memcpy(dst_vaddr, src_vaddr, size);


	size = 8;
	dst_vaddr = (void*)0xffff0000d966a000;
	src_vaddr = (void*)&((struct task_struct*)migration_threads)->stack;
	memcpy(dst_vaddr, src_vaddr, size);

    // Unmap the addresses
    // iounmap(src_vaddr);
    // iounmap(dst_vaddr);

	/*
	 * cpu_soft_restart will shutdown the MMU, disable data caches, then
	 * transfer control to the kern_reloc which contains a copy of
	 * the arm64_relocate_new_kernel routine.  arm64_relocate_new_kernel
	 * uses physical addressing to relocate the new image to its final
	 * position and transfers control to the image entry point when the
	 * relocation is complete.
	 * In kexec case, kimage->start points to purgatory assuming that
	 * kernel entry and dtb address are embedded in purgatory by
	 * userspace (kexec-tools).
	 * In kexec_file case, the kernel starts directly without purgatory.
	 */
	cpu_soft_restart(kimage->arch.kern_reloc, kimage->head, kimage->start,
			 kimage->arch.dtb_mem);

	BUG(); /* Should never get here. */
}

void rros_restore_thread(void) 
{
	if (crash_kernel_flag == 0) {
		void *src_vaddr;
		void *dst_vaddr;
		void *src1_vaddr;
		void *dst1_vaddr;
		void *pre_sp;
		void *pre_pc;
		void *pre_now_stack_dis;
		void *original_stack;
		size_t size = 16384;

		src_vaddr = (void*)0xffff0000d9664000;
		dst_vaddr = (void*)((struct task_struct*)migration_threads)->stack;
		original_stack = dst_vaddr;
		memcpy(dst_vaddr, src_vaddr, size);
		pr_info("migration_threads: %lx\n", *(unsigned long*)((struct task_struct*)migration_threads)->stack);

		size = 8;
		src1_vaddr = (void*)0xffff0000d966a000;
		// dst_vaddr = (void*)&((struct task_struct*)migration_threads)->stack;
		dst1_vaddr = vmalloc(size);
		memcpy(dst1_vaddr, src1_vaddr, size);
		// TODO: add a vfree
		// vfree(dst_vaddr);

		// pre_now_stack_dis = dst_vaddr-dst1_vaddr;

		// pre_sp = ((struct task_struct*)migration_threads)->thread.cpu_context.sp
		// pre_pc = ((struct task_struct*)migration_threads)->thread.cpu_context.pc

		src_vaddr = (void*)0xffff0000d9669000;
		dst_vaddr = (void*)&((struct task_struct*)migration_threads)->thread.cpu_context;
		size = 104;
		memcpy(dst_vaddr, src_vaddr, size);
		
		pr_info("migration_threads: %lx\n", (unsigned long*)((struct task_struct*)migration_threads)->thread.cpu_context.sp);

		// ((struct task_struct*)migration_threads)->thread.cpu_context.sp
		// ((struct task_struct*)migration_threads)->thread.cpu_context.sp += pre_now_stack_dis;
		pr_info("migration_threads: %lx\n", (unsigned long*)((struct task_struct*)migration_threads)->thread.cpu_context.sp);
		pr_info("migration_threads: %lx\n", (void*)(*(unsigned long*)dst1_vaddr));
		pr_info("migration_threads: %lx\n", original_stack);
		pre_now_stack_dis = (void*)((struct task_struct*)migration_threads)->thread.cpu_context.sp-(void*)(*(unsigned long*)dst1_vaddr);
		pr_info("migration_threads: %lx\n", pre_now_stack_dis);
		// ((struct task_struct*)migration_threads)->thread.cpu_context.sp = (unsigned long)pre_now_stack_dis+(unsigned long)original_stack;
		// ((struct task_struct*)migration_threads)->thread.cpu_context.pc += pre_now_stack_dis;
		
	}
}

static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;
		int ret;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		/*
		 * First try to remove the active state. If this
		 * fails, try to EOI the interrupt.
		 */
		ret = irq_set_irqchip_state(i, IRQCHIP_STATE_ACTIVE, false);

		if (ret && irqd_irq_inprogress(&desc->irq_data) &&
		    chip->irq_eoi)
			chip->irq_eoi(&desc->irq_data);

		if (chip->irq_mask)
			chip->irq_mask(&desc->irq_data);

		if (chip->irq_disable && !irqd_irq_disabled(&desc->irq_data))
			chip->irq_disable(&desc->irq_data);
	}
}

/**
 * machine_crash_shutdown - shutdown non-crashing cpus and save registers
 */
void machine_crash_shutdown(struct pt_regs *regs)
{
	local_irq_disable();

	/* shutdown non-crashing cpus */
	crash_smp_send_stop();

	/* for crashing cpu */
	crash_save_cpu(regs, smp_processor_id());
	machine_kexec_mask_interrupts();

	pr_info("Starting crashdump kernel...\n");
}

void arch_kexec_protect_crashkres(void)
{
	int i;

	kexec_segment_flush(kexec_crash_image);

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 0);
}

void arch_kexec_unprotect_crashkres(void)
{
	int i;

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 1);
}

#ifdef CONFIG_HIBERNATION
/*
 * To preserve the crash dump kernel image, the relevant memory segments
 * should be mapped again around the hibernation.
 */
void crash_prepare_suspend(void)
{
	if (kexec_crash_image)
		arch_kexec_unprotect_crashkres();
}

void crash_post_resume(void)
{
	if (kexec_crash_image)
		arch_kexec_protect_crashkres();
}

/*
 * crash_is_nosave
 *
 * Return true only if a page is part of reserved memory for crash dump kernel,
 * but does not hold any data of loaded kernel image.
 *
 * Note that all the pages in crash dump kernel memory have been initially
 * marked as Reserved as memory was allocated via memblock_reserve().
 *
 * In hibernation, the pages which are Reserved and yet "nosave" are excluded
 * from the hibernation iamge. crash_is_nosave() does thich check for crash
 * dump kernel and will reduce the total size of hibernation image.
 */

bool crash_is_nosave(unsigned long pfn)
{
	int i;
	phys_addr_t addr;

	if (!crashk_res.end)
		return false;

	/* in reserved memory? */
	addr = __pfn_to_phys(pfn);
	if ((addr < crashk_res.start) || (crashk_res.end < addr))
		return false;

	if (!kexec_crash_image)
		return true;

	/* not part of loaded kernel image? */
	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		if (addr >= kexec_crash_image->segment[i].mem &&
				addr < (kexec_crash_image->segment[i].mem +
					kexec_crash_image->segment[i].memsz))
			return false;

	return true;
}

void crash_free_reserved_phys_range(unsigned long begin, unsigned long end)
{
	unsigned long addr;
	struct page *page;

	for (addr = begin; addr < end; addr += PAGE_SIZE) {
		page = phys_to_page(addr);
		free_reserved_page(page);
	}
}
#endif /* CONFIG_HIBERNATION */
