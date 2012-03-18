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
	movi	$r0, 3
	syscall	1
.L2:
	! check IFCON is off
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	beqz	$r1, .L3
	movi	$r0, 4
	syscall	1
.L3:
	j	.LPASS

.L0:
	! check IFCON is set
	mfsr	$r1, $psw
	and	$r1, $r1, $r8
	bnez	$r1, .L1
	! FAIL: IFCON not set
	movi	$r0, 1
	syscall	1
.L1:
	addi	$r7, $r7, 1
	ifret
	movi	$r0, 2	! fail to ifret
	syscall	1


.LPASS:
	la	$r0, .Lpstr
	bal	puts
	movi	$r0, 0
	lmw.bim $r6, [$sp], $r9, 10
	ret

.data
	.align 2
.Lpstr:
	.string "pass\n"
.Lfstr:
	.string "fail ifcall\n"
