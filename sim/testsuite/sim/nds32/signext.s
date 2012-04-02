# nds32 test J/JAL in ex9, expected to pass.
# mach:	 all
# as:
# ld:		--defsym=_stack=0x3000000
# output:	pass\n

	.include "utils.inc"

.data
	.align 2
WORD:
	.byte	0x81
	.byte	0x82
HALF:
	.byte	0x83
BYTE:
	.byte	0x84

	.text
	.global	main
main:

.Ldone:
	! $r5 is case counter for sanity check (current 20)
	movi	$r5, 0

	! Set to big endian
	mfsr	$r3, $psw
	ori	$r3, $r3, 32	!psw.be
	mtsr	$r3, $psw

	movi	$r0, 0

	! HALF
	la	$r3, HALF
	move	$r2, 0x8384
	addi	$r5, $r5, 1
	lhi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lhi333	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lh	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	move	$r2, 0xffff8384
	addi	$r5, $r5, 1
	lhsi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lhs	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL


	! BYTE
	move	$r2, 0x84
	la	$r3, BYTE
	addi	$r5, $r5, 1
	lbi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lbi333	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lb	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	move	$r2, 0xffffff84
	addi	$r5, $r5, 1
	lbsi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lbs	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	! Set to little endian
	mfsr	$r3, $psw
	li	$r4, ~32
	and	$r3, $r3, $r4	!psw.be
	mtsr	$r3, $psw

	! HALF
	move	$r2, 0x8483
	la	$r3, HALF
	addi	$r5, $r5, 1
	lhi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lhi333	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lh	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	move	$r2, 0xffff8483
	addi	$r5, $r5, 1
	lhsi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lhs	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	! BYTE
	move	$r2, 0x84
	la	$r3, BYTE
	addi	$r5, $r5, 1
	lbi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lbi333	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lb	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	move	$r2, 0xffffff84
	addi	$r5, $r5, 1
	lbsi	$r1, [$r3 + 0]
	bne	$r1, $r2, .LFAIL
	addi	$r5, $r5, 1
	lbs	$r1, [$r3 + $r0]
	bne	$r1, $r2, .LFAIL

	addi	$r5, $r5, -20
	bnez	$r5, .LFAIL

.LPASS:
	la	$r0, .Lpstr
	bal	puts
	movi	$r0, 0
	syscall 1

.LFAIL:
	la	$r0, .Lfstr
	bal	puts
	movi	$r0, 1
	syscall 1

.Lpstr:
	.string "pass\n"
.Lfstr:
	.string "fail\n"
