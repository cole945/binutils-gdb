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
	movi	$r0, 1		! return to the wrong address
	syscall	1
.L1:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L2
	ret
.L2:
	movi	$r0, 2		! IFCON not cleared
	syscall	1


.Ltest_jral5:
	! test JAL5
	ifcall	.L3
	j	.Ldone
.L3:
	la	$r3, .L4
	jral5	$r3	!! test JRAL5
	movi	$r0, 3		! return to the wrong address
	syscall	1
.L4:
	! check IFCON
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L5
	ret
.L5:
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
