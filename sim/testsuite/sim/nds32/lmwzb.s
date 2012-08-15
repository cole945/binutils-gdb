# nds32 test J/JAL in ex9, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.data
	.align 2
BASE:
	.word	0x11222211
	.word	0x55666655
	.word	0x77000077
	.word	0xaabbbbaa

	.text
	.global	main
main:
	la	$r9, BASE	! load base
	addi	$r10, $r9, #12	! 3 words
	li	$fp, 0

	! expect:
	!	$r6 = 0x11222211
	!	$r7 = 0x55666655
	!	$r8 = 0x77000000(big) or 0x00000077(little)
	!	$fp = 0 (untouched)
	!	$r3 = BASE + 12
	lmwzb.bm	$r6,[$r9],$r8,0x8

	beq	$r9, $r10, 1f
	FAIL	1
1:
	l.w	$r0, BASE
	beq	$r6, $r0, 1f
	FAIL	2
1:
	l.w	$r0, BASE + 4
	beq	$r7, $r0, 1f
	FAIL	3
1:
	l.w	$r0, BASE + 8
	beq	$r8, $r0, 1f
	FAIL	4
1:
	li	$r0, 0
	beq	$fp, $r0, 1f
	FAIL	5
1:
	PASS
	EXIT	0


.Ldone:
