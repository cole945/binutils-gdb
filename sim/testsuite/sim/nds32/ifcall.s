# nds32 test sanity, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

	.text
	.global main
main:
	smw.adm $r6, [$sp], $r9, 10

	movi    $r8, 32768	! bit-15 for IFCON

	movi    $r7, 0

	ifcall  .L0
	addi    $r7, $r7, -1
	! check $r7 == 0
	beqz	$r7, .L2
	FAIL	3
.L2:
	! check IFCON is off
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .L3
	FAIL	4
.L3:
	PASS
	EXIT	0

.L0:
	! check IFCON is set
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L1
	! FAIL: IFCON not set
	FAIL	1
.L1:
	addi	$r7, $r7, 1
	ifret
	FAIL	2	! fail to ifret


.data
	.align 2
.Lpstr:
	.string "pass\n"
.Lfstr:
	.string "fail ifcall\n"
