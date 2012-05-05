#ifndef NDS32_LINUX
#define NDS32_LINUX

#define ALIGN(x, a)		((x) & ~(a-1))
#define ROUNDUP(x, a)		(ALIGN ((x) + ((a) - 1), a))

#define PAGE_SIZE		0x1000
#define PAGE_ALIGN(x)		ALIGN (x, PAGE_SIZE)
#define PAGE_ROUNDUP(x)		ROUNDUP (x, PAGE_SIZE)

#define TASK_SIZE		0xbf000000
#define STACK_TOP		TASK_SIZE
#define TASK_UNMAPPED_BASE	PAGE_ALIGN (TASK_SIZE / 3)

#endif
