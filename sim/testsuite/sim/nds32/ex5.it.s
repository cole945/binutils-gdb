# nds32 test J/JAL in ex9, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.section	.ex9.itable, "a"
	.align	2
.LITB0:
	addi	$r7, $r7, 13
.LITB_J:
	j	.LITB_J
.LITB_JAL:
	jal	.LITB_JAL
	jr	$r8

	.text
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

	beqz	$r7, test_j32
	la	$r0, .Lfstr_n32
	b	.LFAIL


test_j32:
	!	j > 32
	! fix the entry in table
	lwi	$r7, [$r9 + 4]
	la	$r0, test_jal	! fix this address in
	srli	$r0, $r0, 1
	mfsr	$r8, $psw
	andi	$r8, $r8, 32
	bnez	$r8, 1f
	bal	swap
1:
	or	$r0, $r0, $r7
	swi	$r0, [$r9 + 4]

	ex9.it	1
	la	$r0, .Lfstr_j32
	b	.LFAIL


test_jal:
	!	jal > 32
	! fix the entry in table
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
	ex9.it	2
	beqz	$r7, test_jr
	la	$r0, .Lfstr_jal
	j	.LFAIL

test_jal_call:
	addi	$r7, $r7, -1
	ret
	beqz	$r7, test_jr
	la	$r0, .Lfstr_jal
	j	.LFAIL

test_jr:
	!	jr > 32
	la	$r8, .Ldone
	ex9.it	3
	la	$r0, .Lfstr_jr
	j	.LFAIL

	!	jral > 32

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
.Lfstr_n32:
	.string "fall: addi in ex9.it (<32)\n"
.Lfstr_j32:
	.string "fail: j in ex9.it (<32)\n"
.Lfstr_jal:
	.string "fail: jal in ex9.it (<32)\n"
.Lfstr_jr:
	.string "fail: jr in ex9.it (<32)\n"
