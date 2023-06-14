.386
.model flat, stdcall
option casemap: none

.data 
	array dd 10h dup (3, 7, 2, 4, 10, 5, 8, 6, 1, 9)
	arr_length dd 0Ah

.code

start:
	mov esi, offset array
	mov edx, 0	; i

outer:
	
	mov ecx, 0	; j
	mov ebx, arr_length
	sub ebx, edx
	dec ebx		; limit n - i - 1
	
	inner:
		mov eax, dword ptr [esi + 4*ecx]	;eax <= a[j]
		cmp eax, [esi + 4*ecx + 4]			
		jl no_swap				 ;a[j] < a[j+1] OK
		
	swap: 
		xchg eax, [esi + 4*ecx + 4]
		mov [esi + 4*ecx], eax		;a[j], a[j+1] = a[j+1], a[j]
	
	no_swap:
		inc ecx
		cmp ecx, ebx
		jl inner

	inc edx
	cmp edx, dword ptr [arr_length]
	jl outer

end start