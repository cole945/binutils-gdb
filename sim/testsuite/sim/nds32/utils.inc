	.text
	.align	2
	.globl	swap
	.type	swap, @function
swap:
	! unsigned int
	! swap (unsigned int x)
	! {
	!   return (x >> 24) |
	!     ((x << 8) & 0x00FF0000) |
	!     ((x >> 8) & 0x0000FF00) |
	!     (x << 24);
	! }
	slli	$r3, $r0, 24
	srli	$r1, $r0, 24
	or	$r1, $r3, $r1
	sethi	$r3, hi20(16711680)
	slli	$r2, $r0, 8
	and	$r2, $r2, $r3
	or	$r1, $r1, $r2
	srli	$r0, $r0, 8
	movi	$r2, 65280
	and	$r0, $r0, $r2
	or	$r0, $r1, $r0
	ret
	.size	swap, .-swap



	.align 2
	.global	puts
	.type	puts, @function
puts:
	ori	$r1, $r0, 0
	movi	$r2, 0
1:
	lbi.bi	$r3, [$r0], 1
	beqz	$r3, 2f
	addi	$r2, $r2, 1
	b	1b
2:
	movi	$r0, 1
	syscall 5
	ret
	.size	puts, .-puts

	.align 2
	.global	_start
	.type	_start, @function
_start:
	la	$sp, _stack
	bal	main
	syscall	1
	.size	_start, .-_start
