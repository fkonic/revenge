.386
.model flat, stdcall
option casemap: none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.data 
	openError db "Error opening file", 0
	fileName db "C:\Documents and Settings\Hunter\Desktop\DZ\ulaz.txt", 0
	errorCaption db "Error", 0
	succesCaption db "Done", 0
	errorRead db "Unable to read from file", 0
	fileHandle dd 0h
	
	fileSize dd 0h
	bytesRead dd 0h

	outputFile db "izlaz.txt", 0
	outputHandle dd 0h
	bytesWritten dd 0h
	
	numBuffer dd 1024 dup(?)	;Read Buffer
	

.code

start:

;CreateFileA
	push NULL
	push FILE_ATTRIBUTE_ARCHIVE
	push OPEN_EXISTING
	push NULL
	push 0 ;FILE_SHARE_READ
	push GENERIC_READ
	push offset fileName
	call [CreateFileA]
	mov dword ptr [fileHandle], eax

;GetFileSize
	push NULL
	push fileHandle
	call [GetFileSize]
	mov dword ptr [fileSize], eax

;VirtualAlloc
	push PAGE_READWRITE
	push MEM_RESERVE
	push 1024	;proizvoljno ogranicenje na 1 kB
	push 0
	call [VirtualAlloc]
	mov dword ptr [numBuffer], eax

;ReadFile
	push NULL
	push offset bytesRead
	push dword ptr [fileSize]			;tu treba filesize
	push offset numBuffer
	push dword ptr [fileHandle]
	call [ReadFile]



;SORT
	mov esi, offset numBuffer
	mov edx, 0	; i

outer:
	
	mov ecx, 0	; j
	mov ebx, dword ptr bytesRead
	sub ebx, edx
	dec ebx		; limit n - i - 1
	
	inner:
		mov al, byte ptr [esi + ecx]	; al <= a[j]
		cmp al, [esi + ecx + 1]			
		jl no_swap				 ;a[j] < a[j+1] OK
		
	swap: 
		xchg al, [esi + ecx + 1]
		mov [esi + ecx], al	;a[j], a[j+1] = a[j+1], a[j]
	
	no_swap:
		inc ecx
		cmp ecx, ebx
		jl inner

	inc edx
	cmp edx, dword ptr [bytesRead]
	jl outer

;

;CreateFileA
	push NULL
	push FILE_ATTRIBUTE_ARCHIVE
	push CREATE_NEW
	push NULL
	push 0 ;FILE_SHARE_READ
	push GENERIC_READ OR GENERIC_WRITE
	push offset outputFile
	call [CreateFileA]
	mov dword ptr [outputHandle], eax

;WriteFile
	push NULL
	push offset bytesWritten
	push dword ptr [fileSize]
	push offset numBuffer
	push dword ptr [outputHandle]
	call [WriteFile]

;VirtualFree
	push MEM_RELEASE
	push 0
	push offset numBuffer
	call [VirtualFree]

;closing handles
	push dword ptr [outputHandle]
	call [CloseHandle]

	push dword ptr [fileHandle]
	call [CloseHandle]

end start

