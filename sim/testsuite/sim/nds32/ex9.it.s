# nds32 test J/JAL in ex9, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.section	.ex9.itable, "a"
	.space	32 * 4, 0
.L32:
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

	la	$r9, .L32	! address of ITB entry 32

	!	normal instruction >= 32
	movi	$r7, 17
	ex9.it	32
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
	bal	swap
	or	$r0, $r0, $r7
	swi	$r0, [$r9 + 4]

	ex9.it	33
	la	$r0, .Lfstr_j32
	b	.LFAIL


test_jal:
	!	jal > 32
	! fix the entry in table
	lwi	$r7, [$r9 + 8]
	la	$r0, test_jal_call	! fix this address in
	srli	$r0, $r0, 1
	bal	swap
	or	$r0, $r0, $r7
	swi	$r0, [$r9 + 8]

	movi	$r7, 1
	ex9.it	34
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
	ex9.it	35
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
	.string "fall: addi in ex9.it (>=32)\n"
.Lfstr_j32:
	.string "fail: j in ex9.it (>=32)\n"
.Lfstr_jal:
	.string "fail: jal in ex9.it (>=32)\n"
.Lfstr_jr:
	.string "fail: jr in ex9.it (>=32)\n"
