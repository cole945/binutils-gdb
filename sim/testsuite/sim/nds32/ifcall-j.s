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
	movi	$r0, 1		! not jump
	syscall	1
.L1:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_j8
	movi	$r0, 2		! IFCON not cleared
	syscall	1

.Ltest_j8:
	! test J8
	ifcall	.L2
	nop
.L2:
	j8	.L3		!! test J8
	movi	$r0, 3		! not jump
	syscall	1
.L3:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_jr
	movi	$r0, 4		! IFCON not cleared
	syscall	1

.Ltest_jr:
	! test JR
	ifcall	.L4
	nop
.L4:
	la	$r9, .L5
	jr	$r9		!! test JR
	movi	$r0, 3		! not jump
	syscall	1
.L5:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ltest_jr5
	movi	$r0, 4		! IFCON not cleared
	syscall	1

.Ltest_jr5:
	! test JR
	ifcall	.L6
	nop
.L6:
	la	$r3, .L7
	jr5	$r3		!! test JR
	movi	$r0, 3		! not jump
	syscall	1
.L7:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .Ldone
	movi	$r0, 4		! IFCON not cleared
	syscall	1


.Ldone:
	la	$r0, .Lpstr
	bal	puts

	movi	$r0, 0
	lmw.bim	$r6, [$sp], $r9, 10
	ret

.LFAIL:
	bal	puts
	movi	$r0, 1
	syscall 1

.LPASS:
	bal	puts
	movi	$r0, 0
	syscall 1

.Lpstr:
	.string "pass\n"
