# nds32 beqc/bnec, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n*MWA*\n\n
# xerror:

	.include "utils.inc"

	.data
	.align 2
WORD:
	.byte	0x80
	.byte	0x81
HALF:
	.byte	0x82
	.byte	0x83
	.byte	0x84
	.byte	0x85
	.byte	0x86
	.byte	0x87

	.text
	.global main
main:
	smw.adm $sp, [$sp], $sp, 10

	! Set to big endian
	mfsr	$r3, $psw
	ori	$r3, $r3, 32	!psw.be
	mtsr	$r3, $psw

	la	$r9, HALF
	lmw.bi	$r0, [$r9], $r0, 0
	li	$r1, 0x82838485
	beq	$r0, $r1, 1f
	FAIL	1

1:
	li	$r0, 0x12345678
	smw.bi	$r0, [$r9], $r0, 0

	! Set to little endian
	mfsr	$r3, $psw
	li	$r4, ~32
	and	$r3, $r3, $r4	!psw.be
	mtsr	$r3, $psw

	la	$r9, HALF
	lmw.bi	$r0, [$r9], $r0, 0
	li	$r1, 0x78563412
	beq	$r0, $r1, 1f
	FAIL	2
1:
	li	$r0, 0xaabbccdd
	smw.bi	$r0, [$r9], $r0, 0

	la	$r9, WORD
	lwi	$r0, [$r9 + 0]
	li	$r1, 0xccdd8180
	beq	$r0, $r1, 1f
	FAIL	3
1:


	la	$r0, LPASS_STR
	bal	puts

	la	$r9, HALF
	lmwa.bi	$r0, [$r9], $r0, 0	! This shell fail

	FAIL	4
