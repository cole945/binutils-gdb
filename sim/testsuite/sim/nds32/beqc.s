# nds32 beqc/bnec, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

	.text
	.global main
main:
	smw.adm $sp, [$sp], $sp, 10

	movi    $r7, 13
.L0:
	! test fall through
	beqc	$r7, 13, .L1
	la	$r0, .Lfstr0
	j	.LFAIL	! eq, but not take
.L1:
	beqc	$r7, 17, .L2
	bnec	$r7, 17, .L3
	la	$r0, .Lfstr1
	j	.LFAIL	! ne, but not take

.L2:
	la	$r0, .Lfstr2
	j	.LFAIL	! ne, but take

.L3:
	bnec	$r7, 13, .L4
	la	$r0, .Lpstr
	j	.LPASS

.L4:
	la	$r0, .Lfstr3
	j	.LFAIL	! eq, but take


.LPASS:
	bal	puts
	movi	$r0, 0
.LOUT:
	lmw.bim $sp, [$sp], $sp, 10
	ret

.LFAIL:
	bal	puts
	movi	$r0, 1
	b	.LOUT

.data
	.align 2
.Lpstr:
	.string "pass\n"
.Lfstr0:
	.string "fail: eq, but not take\n"
.Lfstr1:
	.string "fail: ne, but not take\n"
.Lfstr2:
	.string "fail: ne, but take\n"
.Lfstr3:
	.string "fail: eq, but take\n"
