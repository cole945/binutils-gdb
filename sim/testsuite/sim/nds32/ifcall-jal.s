# nds32 test J/J8/JR in ifcall, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

	.text
	.global	main
main:
	smw.adm $r6, [$sp], $r9, 10

	movi    $r8, 32768	! bit-15 for IFCON

	! test JAL
	ifcall	.L0
	j	.Ltest_jral5
.L0:
	jal	.L1		!! test J
	FAIL	1		! return to the wrong address

.L1:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L2
	ret
.L2:
	FAIL	2		! IFCON not cleared

.Ltest_jral5:
	! test JAL5
	ifcall	.L3
	PASS
.L3:
	la	$r3, .L4
	jral5	$r3	!! test JRAL5
	FAIL	3		! return to the wrong address
.L4:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L5
	ret
.L5:
	FAIL	4		! IFCON not cleared


.Lpstr:
	.string "pass\n"
