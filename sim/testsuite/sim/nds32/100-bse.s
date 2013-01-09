# nds32 bit stream extraction (basic)
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

	li	$r6, 0x12345678
	li	$r7, 0x87654321

	li	$r10, 0xb0c	! extract 12 bits from 12 bits
	bse	$r8, $r6, $r10	! 456
	bse	$r9, $r7, $r10	! 543

	li	$r1, 0x456
	li	$r2, 0x543

	beq	$r8, $r1, 1f
	PUTS	.Lfstr0

1:
	beq	$r9, $r2, 1f
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
.Lfstr0: .string "fail: bse test 1\n"
.Lfstr1: .string "fail: bse test 2\n"
