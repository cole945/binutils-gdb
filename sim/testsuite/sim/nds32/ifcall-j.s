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

	! test J
	ifcall	.L0
	nop
.L0:
	j	.L1		!! test J
	FAIL	1		! not jump
.L1:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_j8
	FAIL	2		! IFCON not cleared

.Ltest_j8:
	! test J8
	ifcall	.L2
	nop
.L2:
	j8	.L3		!! test J8
	FAIL	3		! not jump
.L3:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_jr
	FAIL	4		! IFCON not cleared

.Ltest_jr:
	! test JR
	ifcall	.L4
	nop
.L4:
	la	$r9, .L5
	jr	$r9		!! test JR
	FAIL	5		! not jump
.L5:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_jr5
	FAIL	6		! IFCON not cleared

.Ltest_jr5:
	! test JR
	ifcall	.L6
	nop
.L6:
	la	$r3, .L7
	jr5	$r3		!! test JR
	FAIL	7		! not jump
.L7:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ldone
	FAIL	8		! IFCON not cleared


.Ldone:
	la	$r0, .Lpstr
	bal	puts

	movi	$r0, 0
	lmw.bim	$r6, [$sp], $r9, 10
	ret

.Lpstr:
	.string "pass\n"
