# nds32 bit stream packing (basic)
# mach:	 	all
# as:		-mbaseline=V3 -mext-perf2
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.data
	.align 2

	.text
	.global main
main:
	smw.adm $r6, [$sp], $r25, 10

	! inputs
	li	$r6, 0x12345678
	li	$r7, 0x87654321
	li	$r11, 0xabc
	! expects
	li	$r8, 0x123abc78
	li	$r9, 0x876abc21

	li	$r10, 0xb0c	! packing 12 bits to 12 bits
	bsp	$r6, $r11, $r10
	bsp	$r7, $r11, $r10

	beq	$r8, $r6, 1f
	PUTS	.Lfstr0

1:
	beq	$r9, $r7, 1f
	PUTS	.Lfstr1

1:
	bnez	$r0, 1f
	PUTS	.Lpstr
	movi	$r0, 0
1:
	lmw.bim $r6, [$sp], $r25, 10
	ret

.section .rodata
	.align 2
.Lpstr:	 .string "pass\n"
.Lfstr0: .string "fail: bsp test 1\n"
.Lfstr1: .string "fail: bsp test 2\n"
