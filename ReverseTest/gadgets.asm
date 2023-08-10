.code

__int2d PROC
	int 2dh
__int2d ENDP

GetCPUID PROC
	push rbp
	mov rbp, rsp
	push rax
	push rbx
	push rcx
	push rdx
	mov rax, 1
	cpuid
	mov rax, rcx
	pop rbx
	pop rcx
	pop rdx
	leave
	ret
GetCPUID ENDP

END