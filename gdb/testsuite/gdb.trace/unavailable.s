	.file	"unavailable.cc"
	.globl	globalc
	.bss
	.type	globalc, @object
	.size	globalc, 1
globalc:
	.zero	1
	.globl	globali
	.align 4
	.type	globali, @object
	.size	globali, 4
globali:
	.zero	4
	.globl	globalf
	.align 4
	.type	globalf, @object
	.size	globalf, 4
globalf:
	.zero	4
	.globl	globald
	.align 8
	.type	globald, @object
	.size	globald, 8
globald:
	.zero	8
	.globl	globalstruct
	.align 16
	.type	globalstruct, @object
	.size	globalstruct, 24
globalstruct:
	.zero	24
	.globl	globalp
	.align 8
	.type	globalp, @object
	.size	globalp, 8
globalp:
	.zero	8
	.globl	globalarr
	.align 32
	.type	globalarr, @object
	.size	globalarr, 64
globalarr:
	.zero	64
	.globl	g_smallstruct
	.align 4
	.type	g_smallstruct, @object
	.size	g_smallstruct, 4
g_smallstruct:
	.zero	4
	.globl	g_smallstruct_b
	.align 4
	.type	g_smallstruct_b, @object
	.size	g_smallstruct_b, 4
g_smallstruct_b:
	.zero	4
	.globl	g_string_unavail
	.type	g_string_unavail, @object
	.size	g_string_unavail, 12
g_string_unavail:
	.zero	12
	.globl	g_string_partial
	.type	g_string_partial, @object
	.size	g_string_partial, 12
g_string_partial:
	.zero	12
	.globl	g_string_p
	.align 8
	.type	g_string_p, @object
	.size	g_string_p, 8
g_string_p:
	.zero	8
	.globl	tarray
	.align 32
	.type	tarray, @object
	.size	tarray, 64
tarray:
	.zero	64
	.globl	a
	.align 4
	.type	a, @object
	.size	a, 4
a:
	.zero	4
	.globl	b
	.align 4
	.type	b, @object
	.size	b, 4
b:
	.zero	4
	.globl	c
	.align 4
	.type	c, @object
	.size	c, 4
c:
	.zero	4
	.globl	g_int
	.align 4
	.type	g_int, @object
	.size	g_int, 4
g_int:
	.zero	4
	.globl	g_ref
	.section	.rodata
	.align 8
	.type	g_ref, @object
	.size	g_ref, 8
g_ref:
	.quad	g_int
	.section	.text._ZN9StructRefC2Ej,"axG",@progbits,_ZN9StructRefC5Ej,comdat
	.align 2
	.weak	_ZN9StructRefC2Ej
	.type	_ZN9StructRefC2Ej, @function
_ZN9StructRefC2Ej:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movq	-8(%rbp), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, 8(%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	_ZN9StructRefC2Ej, .-_ZN9StructRefC2Ej
	.weak	_ZN9StructRefC1Ej
	.set	_ZN9StructRefC1Ej,_ZN9StructRefC2Ej
	.section	.text._ZN9StructRef5clearEv,"axG",@progbits,_ZN9StructRef5clearEv,comdat
	.align 2
	.weak	_ZN9StructRef5clearEv
	.type	_ZN9StructRef5clearEv, @function
_ZN9StructRef5clearEv:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$0, (%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	_ZN9StructRef5clearEv, .-_ZN9StructRef5clearEv
	.globl	struct_b
	.bss
	.align 32
	.type	struct_b, @object
	.size	struct_b, 40048
struct_b:
	.zero	40048
	.globl	_ZN7StructB15static_struct_aE
	.align 32
	.type	_ZN7StructB15static_struct_aE, @object
	.size	_ZN7StructB15static_struct_aE, 40024
_ZN7StructB15static_struct_aE:
	.zero	40024
	.globl	g_structref
	.align 16
	.type	g_structref, @object
	.size	g_structref, 16
g_structref:
	.zero	16
	.globl	g_structref_p
	.data
	.align 8
	.type	g_structref_p, @object
	.size	g_structref_p, 8
g_structref_p:
	.quad	g_structref
	.section	.text._ZN4BaseC2Ev,"axG",@progbits,_ZN4BaseC5Ev,comdat
	.align 2
	.weak	_ZN4BaseC2Ev
	.type	_ZN4BaseC2Ev, @function
_ZN4BaseC2Ev:
.LFB7:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movl	$2, (%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	_ZN4BaseC2Ev, .-_ZN4BaseC2Ev
	.weak	_ZN4BaseC1Ev
	.set	_ZN4BaseC1Ev,_ZN4BaseC2Ev
	.section	.text._ZN6MiddleC2Ev,"axG",@progbits,_ZN6MiddleC2Ev,comdat
	.align 2
	.weak	_ZN6MiddleC2Ev
	.type	_ZN6MiddleC2Ev, @function
_ZN6MiddleC2Ev:
.LFB10:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	-16(%rbp), %rax
	movq	(%rax), %rdx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movq	-8(%rbp), %rax
	movl	$3, 8(%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE10:
	.size	_ZN6MiddleC2Ev, .-_ZN6MiddleC2Ev
	.section	.text._ZN7DerivedC1Ev,"axG",@progbits,_ZN7DerivedC1Ev,comdat
	.align 2
	.weak	_ZN7DerivedC1Ev
	.type	_ZN7DerivedC1Ev, @function
_ZN7DerivedC1Ev:
.LFB14:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	addq	$28, %rax
	movq	%rax, %rdi
	call	_ZN4BaseC2Ev
	movl	$_ZTT7Derived+16, %eax
	movq	-8(%rbp), %rdx
	addq	$16, %rdx
	movq	%rax, %rsi
	movq	%rdx, %rdi
	call	_ZN6MiddleC2Ev
	movl	$_ZTV7Derived+32, %edx
	movq	-8(%rbp), %rax
	movq	%rdx, (%rax)
	movl	$16, %edx
	movq	-8(%rbp), %rax
	addq	%rax, %rdx
	movl	$_ZTV7Derived+56, %eax
	movq	%rax, (%rdx)
	movq	-8(%rbp), %rax
	movl	$4, 8(%rax)
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE14:
	.size	_ZN7DerivedC1Ev, .-_ZN7DerivedC1Ev
	.globl	derived_unavail
	.bss
	.align 32
	.type	derived_unavail, @object
	.size	derived_unavail, 32
derived_unavail:
	.zero	32
	.globl	derived_partial
	.align 32
	.type	derived_partial, @object
	.size	derived_partial, 32
derived_partial:
	.zero	32
	.globl	derived_whole
	.align 32
	.type	derived_whole, @object
	.size	derived_whole, 32
derived_whole:
	.zero	32
	.section	.text._ZN7VirtualD2Ev,"axG",@progbits,_ZN7VirtualD5Ev,comdat
	.align 2
	.weak	_ZN7VirtualD2Ev
	.type	_ZN7VirtualD2Ev, @function
_ZN7VirtualD2Ev:
.LFB16:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	$_ZTV7Virtual+16, (%rax)
	movl	$0, %eax
	testl	%eax, %eax
	je	.L6
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZdlPv
.L6:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE16:
	.size	_ZN7VirtualD2Ev, .-_ZN7VirtualD2Ev
	.weak	_ZN7VirtualD1Ev
	.set	_ZN7VirtualD1Ev,_ZN7VirtualD2Ev
	.section	.text._ZN7VirtualD0Ev,"axG",@progbits,_ZN7VirtualD0Ev,comdat
	.align 2
	.weak	_ZN7VirtualD0Ev
	.type	_ZN7VirtualD0Ev, @function
_ZN7VirtualD0Ev:
.LFB18:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZN7VirtualD1Ev
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	_ZdlPv
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE18:
	.size	_ZN7VirtualD0Ev, .-_ZN7VirtualD0Ev
	.section	.text._ZN7VirtualC2Ev,"axG",@progbits,_ZN7VirtualC5Ev,comdat
	.align 2
	.weak	_ZN7VirtualC2Ev
	.type	_ZN7VirtualC2Ev, @function
_ZN7VirtualC2Ev:
.LFB20:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	$_ZTV7Virtual+16, (%rax)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE20:
	.size	_ZN7VirtualC2Ev, .-_ZN7VirtualC2Ev
	.weak	_ZN7VirtualC1Ev
	.set	_ZN7VirtualC1Ev,_ZN7VirtualC2Ev
	.globl	virtual_partial
	.bss
	.align 16
	.type	virtual_partial, @object
	.size	virtual_partial, 16
virtual_partial:
	.zero	16
	.globl	virtualp
	.data
	.align 8
	.type	virtualp, @object
	.size	virtualp, 8
virtualp:
	.quad	virtual_partial
	.text
	.type	_ZL5beginv, @function
_ZL5beginv:
.LFB22:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE22:
	.size	_ZL5beginv, .-_ZL5beginv
	.type	_ZL3endv, @function
_ZL3endv:
.LFB23:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE23:
	.size	_ZL3endv, .-_ZL3endv
	.globl	_Z14args_test_funccifd11TEST_STRUCTPi
	.type	_Z14args_test_funccifd11TEST_STRUCTPi, @function
_Z14args_test_funccifd11TEST_STRUCTPi:
.LFB24:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, %eax
	movl	%esi, -24(%rbp)
	movss	%xmm0, -28(%rbp)
	movsd	%xmm1, -40(%rbp)
	movq	%rdx, -48(%rbp)
	movb	%al, -20(%rbp)
	movsbl	-20(%rbp), %edx
	movl	-24(%rbp), %eax
	addl	%edx, %eax
	cvtsi2ss	%eax, %xmm0
	addss	-28(%rbp), %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	movapd	%xmm0, %xmm1
	addsd	-40(%rbp), %xmm1
	movl	20(%rbp), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm0, %xmm1
	movq	-48(%rbp), %rax
	addq	$4, %rax
	movl	(%rax), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -4(%rbp)
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE24:
	.size	_Z14args_test_funccifd11TEST_STRUCTPi, .-_Z14args_test_funccifd11TEST_STRUCTPi
	.globl	_Z15local_test_funcv
	.type	_Z15local_test_funcv, @function
_Z15local_test_funcv:
.LFB25:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movb	$11, -69(%rbp)
	movl	$12, -68(%rbp)
	movl	.LC0(%rip), %eax
	movl	%eax, -64(%rbp)
	movabsq	$4624296097384025293, %rax
	movq	%rax, -56(%rbp)
	movb	$15, -32(%rbp)
	movl	$16, -28(%rbp)
	movl	.LC2(%rip), %eax
	movl	%eax, -24(%rbp)
	movabsq	$4625984947244289229, %rax
	movq	%rax, -16(%rbp)
	movl	$121, -48(%rbp)
	movl	$122, -44(%rbp)
	movl	$123, -40(%rbp)
	movl	$124, -36(%rbp)
	movsbl	-69(%rbp), %edx
	movl	-68(%rbp), %eax
	addl	%edx, %eax
	cvtsi2ss	%eax, %xmm0
	addss	-64(%rbp), %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	movapd	%xmm0, %xmm1
	addsd	-56(%rbp), %xmm1
	movl	-28(%rbp), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm0, %xmm1
	movl	-44(%rbp), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -60(%rbp)
	movl	-60(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE25:
	.size	_Z15local_test_funcv, .-_Z15local_test_funcv
	.globl	_Z18reglocal_test_funcv
	.type	_Z18reglocal_test_funcv, @function
_Z18reglocal_test_funcv:
.LFB26:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	.cfi_offset 14, -24
	.cfi_offset 13, -32
	.cfi_offset 12, -40
	.cfi_offset 3, -48
	movl	$11, %r14d
	movl	$12, %ebx
	movss	.LC0(%rip), %xmm3
	movsd	.LC1(%rip), %xmm2
	movb	$15, -64(%rbp)
	movl	$16, -60(%rbp)
	movl	.LC2(%rip), %eax
	movl	%eax, -56(%rbp)
	movabsq	$4625984947244289229, %rax
	movq	%rax, -48(%rbp)
	movq	%r12, %rdx
	movabsq	$-4294967296, %rax
	andq	%rdx, %rax
	orq	$121, %rax
	movq	%rax, %r12
	movq	%r12, %rax
	movl	%eax, %edx
	movabsq	$523986010112, %rax
	orq	%rdx, %rax
	movq	%rax, %r12
	movq	%r13, %rdx
	movabsq	$-4294967296, %rax
	andq	%rdx, %rax
	orq	$123, %rax
	movq	%rax, %r13
	movq	%r13, %rax
	movl	%eax, %edx
	movabsq	$532575944704, %rax
	orq	%rdx, %rax
	movq	%rax, %r13
	movsbl	%r14b, %eax
	addl	%ebx, %eax
	cvtsi2ss	%eax, %xmm0
	addss	%xmm3, %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	addsd	%xmm0, %xmm2
	movapd	%xmm2, %xmm1
	movl	-60(%rbp), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm0, %xmm1
	movq	%r12, %rax
	sarq	$32, %rax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -68(%rbp)
	movl	-68(%rbp), %eax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE26:
	.size	_Z18reglocal_test_funcv, .-_Z18reglocal_test_funcv
	.globl	_Z19statlocal_test_funcv
	.type	_Z19statlocal_test_funcv, @function
_Z19statlocal_test_funcv:
.LFB27:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movb	$11, _ZZ19statlocal_test_funcvE4locc(%rip)
	movl	$12, _ZZ19statlocal_test_funcvE4loci(%rip)
	movl	.LC0(%rip), %eax
	movl	%eax, _ZZ19statlocal_test_funcvE4locf(%rip)
	movabsq	$4624296097384025293, %rax
	movq	%rax, _ZZ19statlocal_test_funcvE4locd(%rip)
	movb	$15, _ZZ19statlocal_test_funcvE5locst(%rip)
	movl	$16, _ZZ19statlocal_test_funcvE5locst+4(%rip)
	movl	.LC2(%rip), %eax
	movl	%eax, _ZZ19statlocal_test_funcvE5locst+8(%rip)
	movabsq	$4625984947244289229, %rax
	movq	%rax, _ZZ19statlocal_test_funcvE5locst+16(%rip)
	movl	$121, _ZZ19statlocal_test_funcvE5locar(%rip)
	movl	$122, _ZZ19statlocal_test_funcvE5locar+4(%rip)
	movl	$123, _ZZ19statlocal_test_funcvE5locar+8(%rip)
	movl	$124, _ZZ19statlocal_test_funcvE5locar+12(%rip)
	movzbl	_ZZ19statlocal_test_funcvE4locc(%rip), %eax
	movsbl	%al, %edx
	movl	_ZZ19statlocal_test_funcvE4loci(%rip), %eax
	addl	%edx, %eax
	cvtsi2ss	%eax, %xmm0
	movss	_ZZ19statlocal_test_funcvE4locf(%rip), %xmm1
	addss	%xmm1, %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	movsd	_ZZ19statlocal_test_funcvE4locd(%rip), %xmm1
	addsd	%xmm0, %xmm1
	movl	_ZZ19statlocal_test_funcvE5locst+4(%rip), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm0, %xmm1
	movl	_ZZ19statlocal_test_funcvE5locar+4(%rip), %eax
	cvtsi2sd	%eax, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -4(%rbp)
	movb	$0, _ZZ19statlocal_test_funcvE4locc(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE4loci(%rip)
	movl	.LC4(%rip), %eax
	movl	%eax, _ZZ19statlocal_test_funcvE4locf(%rip)
	movl	$0, %eax
	movq	%rax, _ZZ19statlocal_test_funcvE4locd(%rip)
	movb	$0, _ZZ19statlocal_test_funcvE5locst(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE5locst+4(%rip)
	movl	.LC4(%rip), %eax
	movl	%eax, _ZZ19statlocal_test_funcvE5locst+8(%rip)
	movl	$0, %eax
	movq	%rax, _ZZ19statlocal_test_funcvE5locst+16(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE5locar(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE5locar+4(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE5locar+8(%rip)
	movl	$0, _ZZ19statlocal_test_funcvE5locar+12(%rip)
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE27:
	.size	_Z19statlocal_test_funcv, .-_Z19statlocal_test_funcv
	.globl	_Z17globals_test_funcv
	.type	_Z17globals_test_funcv, @function
_Z17globals_test_funcv:
.LFB28:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, -4(%rbp)
	cvtsi2sd	-4(%rbp), %xmm1
	movzbl	globalc(%rip), %eax
	movsbl	%al, %edx
	movl	globali(%rip), %eax
	addl	%edx, %eax
	cvtsi2ss	%eax, %xmm0
	movss	globalf(%rip), %xmm2
	addss	%xmm2, %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	movsd	globald(%rip), %xmm2
	addsd	%xmm2, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -4(%rbp)
	movzbl	globalstruct(%rip), %eax
	movsbl	%al, %edx
	movl	globalstruct+4(%rip), %eax
	addl	%edx, %eax
	addl	%eax, -4(%rbp)
	cvtsi2sd	-4(%rbp), %xmm1
	movss	globalstruct+8(%rip), %xmm0
	unpcklps	%xmm0, %xmm0
	cvtps2pd	%xmm0, %xmm0
	movsd	globalstruct+16(%rip), %xmm2
	addsd	%xmm2, %xmm0
	addsd	%xmm1, %xmm0
	cvttsd2si	%xmm0, %eax
	movl	%eax, -4(%rbp)
	movl	globalarr+4(%rip), %eax
	addl	%eax, -4(%rbp)
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE28:
	.size	_Z17globals_test_funcv, .-_Z17globals_test_funcv
	.globl	main
	.type	main, @function
main:
.LFB29:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	addq	$-128, %rsp
	movl	%edi, -68(%rbp)
	movq	%rsi, -80(%rbp)
	movq	%rdx, -88(%rbp)
	movl	$0, -52(%rbp)
	call	_ZL5beginv
	movb	$71, globalc(%rip)
	movl	$72, globali(%rip)
	movl	.LC6(%rip), %eax
	movl	%eax, globalf(%rip)
	movabsq	$4634935851503688090, %rax
	movq	%rax, globald(%rip)
	movb	$81, globalstruct(%rip)
	movl	$82, globalstruct+4(%rip)
	movl	.LC8(%rip), %eax
	movl	%eax, globalstruct+8(%rip)
	movabsq	$4635639538945464730, %rax
	movq	%rax, globalstruct+16(%rip)
	movq	$globalstruct, globalp(%rip)
	movl	$0, -52(%rbp)
	jmp	.L25
.L26:
	movl	-52(%rbp), %eax
	cltq
	movl	-52(%rbp), %edx
	movl	%edx, globalarr(,%rax,4)
	addl	$1, -52(%rbp)
.L25:
	cmpl	$14, -52(%rbp)
	jle	.L26
	movb	$101, -32(%rbp)
	movl	$102, -28(%rbp)
	movl	.LC10(%rip), %eax
	movl	%eax, -24(%rbp)
	movabsq	$4637046913829018010, %rax
	movq	%rax, -16(%rbp)
	movl	$111, -48(%rbp)
	movl	$112, -44(%rbp)
	movl	$113, -40(%rbp)
	movl	$114, -36(%rbp)
	movl	$123, g_int(%rip)
	movl	$40048, %edx
	movl	$170, %esi
	movl	$struct_b, %edi
	call	memset
	movl	$40024, %edx
	movl	$170, %esi
	movl	$_ZN7StructB15static_struct_aE, %edi
	call	memset
	movq	$_ZL14g_const_string, struct_b+40040(%rip)
	movabsq	$8031924123371070824, %rax
	movq	%rax, g_string_unavail(%rip)
	movl	$6581362, g_string_unavail+8(%rip)
	movabsq	$8031924123371070824, %rax
	movq	%rax, g_string_partial(%rip)
	movl	$6581362, g_string_partial+8(%rip)
	movq	$_ZL14g_const_string, g_string_p(%rip)
	movl	$1, a(%rip)
	movl	$2, b(%rip)
	movl	$3, c(%rip)
	movl	$0, -52(%rbp)
	leaq	-48(%rbp), %rdx
	movabsq	$4616639978017495450, %rax
	movq	-32(%rbp), %rcx
	movq	%rcx, (%rsp)
	movq	-24(%rbp), %rcx
	movq	%rcx, 8(%rsp)
	movq	-16(%rbp), %rcx
	movq	%rcx, 16(%rsp)
	movq	%rax, -96(%rbp)
	movsd	-96(%rbp), %xmm1
	movss	.LC13(%rip), %xmm0
	movl	$2, %esi
	movl	$1, %edi
	call	_Z14args_test_funccifd11TEST_STRUCTPi
	addl	%eax, -52(%rbp)
	call	_Z15local_test_funcv
	addl	%eax, -52(%rbp)
	call	_Z18reglocal_test_funcv
	addl	%eax, -52(%rbp)
	call	_Z19statlocal_test_funcv
	addl	%eax, -52(%rbp)
	call	_Z17globals_test_funcv
	addl	%eax, -52(%rbp)
	movb	$0, globalc(%rip)
	movl	$0, globali(%rip)
	movl	.LC4(%rip), %eax
	movl	%eax, globalf(%rip)
	movl	$0, %eax
	movq	%rax, globald(%rip)
	movb	$0, globalstruct(%rip)
	movl	$0, globalstruct+4(%rip)
	movl	.LC4(%rip), %eax
	movl	%eax, globalstruct+8(%rip)
	movl	$0, %eax
	movq	%rax, globalstruct+16(%rip)
	movq	$0, globalp(%rip)
	movl	$0, -52(%rbp)
	jmp	.L27
.L28:
	movl	-52(%rbp), %eax
	cltq
	movl	$0, globalarr(,%rax,4)
	addl	$1, -52(%rbp)
.L27:
	cmpl	$14, -52(%rbp)
	jle	.L28
	movl	$40048, %edx
	movl	$0, %esi
	movl	$struct_b, %edi
	call	memset
	movl	$40024, %edx
	movl	$0, %esi
	movl	$_ZN7StructB15static_struct_aE, %edi
	call	memset
	movq	$0, struct_b+40040(%rip)
	movl	$12, %edx
	movl	$0, %esi
	movl	$g_string_unavail, %edi
	call	memset
	movl	$12, %edx
	movl	$0, %esi
	movl	$g_string_partial, %edi
	call	memset
	movq	$0, g_string_p(%rip)
	movl	$0, c(%rip)
	movl	c(%rip), %eax
	movl	%eax, b(%rip)
	movl	b(%rip), %eax
	movl	%eax, a(%rip)
	movl	$0, g_int(%rip)
	movl	$g_structref, %edi
	call	_ZN9StructRef5clearEv
	movq	$0, g_structref_p(%rip)
	call	_ZL3endv
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE29:
	.size	main, .-main
	.weak	_ZTV7Virtual
	.section	.rodata._ZTV7Virtual,"aG",@progbits,_ZTV7Virtual,comdat
	.align 32
	.type	_ZTV7Virtual, @object
	.size	_ZTV7Virtual, 32
_ZTV7Virtual:
	.quad	0
	.quad	_ZTI7Virtual
	.quad	_ZN7VirtualD1Ev
	.quad	_ZN7VirtualD0Ev
	.weak	_ZTV7Derived
	.section	.rodata._ZTV7Derived,"aG",@progbits,_ZTV7Derived,comdat
	.align 32
	.type	_ZTV7Derived, @object
	.size	_ZTV7Derived, 56
_ZTV7Derived:
	.quad	28
	.quad	16
	.quad	0
	.quad	_ZTI7Derived
	.quad	12
	.quad	-16
	.quad	_ZTI7Derived
	.weak	_ZTT7Derived
	.section	.rodata._ZTT7Derived,"aG",@progbits,_ZTV7Derived,comdat
	.align 16
	.type	_ZTT7Derived, @object
	.size	_ZTT7Derived, 24
_ZTT7Derived:
	.quad	_ZTV7Derived+32
	.quad	_ZTV7Derived+56
	.quad	_ZTC7Derived16_6Middle+24
	.hidden	_ZTC7Derived16_6Middle
	.weak	_ZTC7Derived16_6Middle
	.section	.rodata._ZTC7Derived16_6Middle,"aG",@progbits,_ZTV7Derived,comdat
	.align 16
	.type	_ZTC7Derived16_6Middle, @object
	.size	_ZTC7Derived16_6Middle, 24
_ZTC7Derived16_6Middle:
	.quad	12
	.quad	0
	.quad	_ZTI6Middle
	.weak	_ZTS7Virtual
	.section	.rodata._ZTS7Virtual,"aG",@progbits,_ZTS7Virtual,comdat
	.type	_ZTS7Virtual, @object
	.size	_ZTS7Virtual, 9
_ZTS7Virtual:
	.string	"7Virtual"
	.weak	_ZTI7Virtual
	.section	.rodata._ZTI7Virtual,"aG",@progbits,_ZTI7Virtual,comdat
	.align 16
	.type	_ZTI7Virtual, @object
	.size	_ZTI7Virtual, 16
_ZTI7Virtual:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS7Virtual
	.weak	_ZTS7Derived
	.section	.rodata._ZTS7Derived,"aG",@progbits,_ZTS7Derived,comdat
	.type	_ZTS7Derived, @object
	.size	_ZTS7Derived, 9
_ZTS7Derived:
	.string	"7Derived"
	.weak	_ZTI7Derived
	.section	.rodata._ZTI7Derived,"aG",@progbits,_ZTI7Derived,comdat
	.align 32
	.type	_ZTI7Derived, @object
	.size	_ZTI7Derived, 40
_ZTI7Derived:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS7Derived
	.long	0
	.long	1
	.quad	_ZTI6Middle
	.quad	-6141
	.weak	_ZTS6Middle
	.section	.rodata._ZTS6Middle,"aG",@progbits,_ZTS6Middle,comdat
	.type	_ZTS6Middle, @object
	.size	_ZTS6Middle, 8
_ZTS6Middle:
	.string	"6Middle"
	.weak	_ZTI6Middle
	.section	.rodata._ZTI6Middle,"aG",@progbits,_ZTI6Middle,comdat
	.align 32
	.type	_ZTI6Middle, @object
	.size	_ZTI6Middle, 40
_ZTI6Middle:
	.quad	_ZTVN10__cxxabiv121__vmi_class_type_infoE+16
	.quad	_ZTS6Middle
	.long	0
	.long	1
	.quad	_ZTI4Base
	.quad	-6141
	.text
	.type	_Z41__static_initialization_and_destruction_0ii, @function
_Z41__static_initialization_and_destruction_0ii:
.LFB30:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	cmpl	$1, -4(%rbp)
	jne	.L30
	cmpl	$65535, -8(%rbp)
	jne	.L30
	movl	$305419896, %esi
	movl	$g_structref, %edi
	call	_ZN9StructRefC1Ej
	movl	$derived_unavail, %edi
	call	_ZN7DerivedC1Ev
	movl	$derived_partial, %edi
	call	_ZN7DerivedC1Ev
	movl	$derived_whole, %edi
	call	_ZN7DerivedC1Ev
	movl	$virtual_partial, %edi
	call	_ZN7VirtualC1Ev
	movl	$__dso_handle, %edx
	movl	$virtual_partial, %esi
	movl	$_ZN7VirtualD1Ev, %edi
	call	__cxa_atexit
.L30:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE30:
	.size	_Z41__static_initialization_and_destruction_0ii, .-_Z41__static_initialization_and_destruction_0ii
	.section	.rodata
	.type	_ZL14g_const_string, @object
	.size	_ZL14g_const_string, 12
_ZL14g_const_string:
	.string	"hello world"
	.weak	_ZTS4Base
	.section	.rodata._ZTS4Base,"aG",@progbits,_ZTS4Base,comdat
	.type	_ZTS4Base, @object
	.size	_ZTS4Base, 6
_ZTS4Base:
	.string	"4Base"
	.weak	_ZTI4Base
	.section	.rodata._ZTI4Base,"aG",@progbits,_ZTI4Base,comdat
	.align 16
	.type	_ZTI4Base, @object
	.size	_ZTI4Base, 16
_ZTI4Base:
	.quad	_ZTVN10__cxxabiv117__class_type_infoE+16
	.quad	_ZTS4Base
	.text
	.type	_GLOBAL__sub_I_globalc, @function
_GLOBAL__sub_I_globalc:
.LFB31:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$65535, %esi
	movl	$1, %edi
	call	_Z41__static_initialization_and_destruction_0ii
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE31:
	.size	_GLOBAL__sub_I_globalc, .-_GLOBAL__sub_I_globalc
	.section	.init_array,"aw"
	.align 8
	.quad	_GLOBAL__sub_I_globalc
	.local	_ZZ19statlocal_test_funcvE4locc
	.comm	_ZZ19statlocal_test_funcvE4locc,1,1
	.local	_ZZ19statlocal_test_funcvE4loci
	.comm	_ZZ19statlocal_test_funcvE4loci,4,4
	.local	_ZZ19statlocal_test_funcvE4locf
	.comm	_ZZ19statlocal_test_funcvE4locf,4,4
	.local	_ZZ19statlocal_test_funcvE4locd
	.comm	_ZZ19statlocal_test_funcvE4locd,8,8
	.local	_ZZ19statlocal_test_funcvE5locst
	.comm	_ZZ19statlocal_test_funcvE5locst,24,16
	.local	_ZZ19statlocal_test_funcvE5locar
	.comm	_ZZ19statlocal_test_funcvE5locar,16,16
	.section	.rodata
	.align 4
.LC0:
	.long	1096076493
	.align 8
.LC1:
	.long	3435973837
	.long	1076677836
	.align 4
.LC2:
	.long	1099798938
	.align 4
.LC4:
	.long	0
	.align 4
.LC6:
	.long	1116903834
	.align 4
.LC8:
	.long	1118214554
	.align 4
.LC10:
	.long	1120835994
	.align 4
.LC13:
	.long	1079194419
	.hidden	__dso_handle
	.ident	"GCC: (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4"
	.section	.note.GNU-stack,"",@progbits
