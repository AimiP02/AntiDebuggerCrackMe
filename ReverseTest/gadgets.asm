.code

__int2d PROC
	int 2dh
__int2d ENDP

GetCPUid PROC
	mov rax, 1
	cpuid
	ret
GetCPUid ENDP

END