# nds32 test J/JAL in ex5.it (index < 32), expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.section	.ex9.itable, "a"
	.align	2
.LITB0:		addi	$r7, $r7, 13
.LITB_J:	j	.LITB_J
.LITB_JAL:	jal	.LITB_JAL
.LITB_JR:	jr	$r8
.LITB_BEQZ:	beqz	$r8, .LITB_BEQZ

	.text
test_jal_call:
	addi	$r7, $r7, -1
	ret

	.global	main
main:
	smw.adm $r6, [$sp], $r9, 10

	! Load ITB table
	la	$r9, .LITB0
	mtusr	$r9, $ITB

	la	$r9, .LITB0	! address of ITB entry 0

	!	normal instruction >= 32
	movi	$r7, 17
	ex9.it	0
	addi	$r7, $r7, -30

	beqz	$r7, .Ltest_j32
	PUTS	.Lfstr_n32	! FAIL: addi in ex5.it

.Ltest_j32:
	! relocate the entry in table
	lwi	$r7, [$r9 + 4]
	la	$r0, .Ltest_jal	! fix this address in
	srli	$r0, $r0, 1
	mfsr	$r8, $psw
	andi	$r8, $r8, 32
	bnez	$r8, 1f
	bal	swap
1:
	or	$r0, $r0, $r7
	swi	$r0, [$r9 + 4]

	ex9.it	0x1		! j  .Ltest_jal
	PUTS	.Lfstr_j32	! FAIL: j in ex5.it


.Ltest_jal:
	! relocate the entry in table
	lwi	$r7, [$r9 + 8]
	la	$r0, test_jal_call	! fix this address in
	srli	$r0, $r0, 1
	mfsr	$r8, $psw
	andi	$r8, $r8, 32
	bnez	$r8, 1f
	bal	swap
1:
	or	$r0, $r0, $r7
	swi	$r0, [$r9 + 8]

	movi	$r7, 1
	ex9.it	0x2			! test_jal_call for $r7--
	beqz	$r7, .Ltest_jr
	PUTS	.Lfstr_jal		! jal .Ltest_jr

.Ltest_jr:
	la	$r8, .Ldone
	ex9.it	0x3			! jr $r8 (.Ldone)
	PUTS	.Lfstr_jr
	EXIT	1

.Ldone:
	PUTS	.Lpstr

	movi	$r0, 0
	lmw.bim	$r6, [$sp], $r9, 10
	ret

.Lpstr:     .string "pass\n"
.Lfstr_n32: .string "fall: addi in ex9.it (<32)\n"
.Lfstr_j32: .string "fail: j in ex9.it (<32)\n"
.Lfstr_jal: .string "fail: jal in ex9.it (<32)\n"
.Lfstr_jr:  .string "fail: jr in ex9.it (<32)\n"
