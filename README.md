# PMM
Physical Memory Map (PMM)

This repository provides a PoC demonstrating direct physical memory access from usermode through virtual address mapping.
The technique works by manipulating a specific PML4 entry to create a 1:1 mapping of physical memory.

In IA-32e (x64) paging, virtual addresses are translated using a 4-level paging structure:
- Bits 0-11: Page Offset
- Bits 12-20: PT Index
- Bits 21-29: PD Index
- Bits 30-38: PDPT Index
- Bits 39-47: PML4 Index

The PoC works by:
1. Allocating kernel memory for new paging structures (PML4E, PDPT, and PDs)
2. Setting up these structures to create 2MB large pages that directly map to physical memory
3. Replacing a specific PML4 entry (256 in this PoC) to point to our new paging structures
4. Using a canonical virtual address that references this PML4 entry to access physical memory

For example, using PML4 index 256:
- Raw virtual address: 0x0000800000000000 (non-canonical)
- Sign-extended address: 0xFFFF800000000000 (canonical, anatomically the same as the non-canonical address)

To access physical address 0x1000, we add it to our base address:
0xFFFF800000000000 + 0x1000 -> Accesses physical memory at 0x1000

The usermode code demonstrates this on an allocated non paged pool.

The current implementation maps 64GB of physical memory using 2MB large pages for efficiency.

Note: This PoC is for educational purposes only, demonstrating x64 paging mechanisms. It is not meant to be used in production or for any malicious purposes. The memory manager will most likely explode after a while.