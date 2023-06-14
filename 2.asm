.386
.model flat, stdcall
option casemap: none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\Ws2_32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\Ws2_32.lib

.data
	wsaData db 0Bh dup(0h)
	socketHandle dd 0h

	socketParameters db 10h dup (0h)
	socketPort dw 4D2h
	socketAddress db "127.0.0.1", 0h

	storageAddress db 10h dup (0h)
	storageAddressLength db 10h

	connectionHandle dd 0h

	receiveBuffer db 50h dup (0h)
	receivedSize dd 0h

	processInformation db 100h dup (0h)
	startupInformation db 100h dup (0h)

	decimalMask dd 1h, 0ah, 64h, 3e8h   ;potencije broja 10 za pretvorbu PID-a u decimalni oblik  
	processHandle dd 0h
	
	snapHandle dd 0h
	processEntry db 128h dup (0h)

	sendBuffer db 30h dup (0h)
	sendSize dd 0h
	sendBufferCounter dd 0h

	PID db 4h dup (0h)
	ASCIIlookup db "0123456789"

.code
start:
	mov eax, offset wsaData
	push eax
	push 202h
	call [WSAStartup]

	push IPPROTO_TCP
	push SOCK_STREAM
	push AF_INET
	call [socket]
	mov dword ptr [socketHandle], eax

	mov word ptr [socketParameters], AF_INET
	push dword ptr [socketPort]
	call [htons]
	mov dword ptr [socketParameters + 2h], eax
	
	push offset socketAddress
	call [inet_addr]
	mov dword ptr [socketParameters + 4h], eax

	push 10h
	push offset socketParameters
	push dword ptr [socketHandle]
	call [bind]

	push 1h
	push dword ptr [socketHandle]
	call [listen]

	push offset storageAddressLength
	push offset storageAddress
	push dword ptr [socketHandle]
	call [accept]
	mov dword ptr [connectionHandle], eax

receive_comm:
	push 0h
	push 50h
	push offset receiveBuffer
	push dword ptr [connectionHandle]
	call [recv]
	mov dword ptr [receivedSize], eax

	;PARSE
	cmp word ptr [receiveBuffer], 2065h
	je echo_comm
	cmp word ptr [receiveBuffer], " k"
	je kill_comm
	cmp word ptr [receiveBuffer], " r"
	je run_comm
	cmp word ptr [receiveBuffer], " l"
	je list

echo_comm:
	mov ebx, dword ptr [receivedSize]
	mov byte ptr [receiveBuffer + ebx - 1h], 00h

	mov ecx, offset [receiveBuffer + 2h]
	mov eax, MB_OK

	push eax
	push ecx
	push ecx
	push 0h
	call [MessageBox]

	jmp receive_comm

kill_comm:
	cmp word ptr [receiveBuffer + 2h], "em"
	je epilogue

	mov ebx, dword ptr [receivedSize]
	mov byte ptr [receiveBuffer + ebx - 1h], 00h
	mov edi, offset [receiveBuffer + 2h]
    sub ebx, 3h
    mov ecx, ebx

;;konverzija PID-a iz ascii u dekadski oblik
sub_ascii:  
    sub byte ptr [edi], 30h
    inc edi
    loop sub_ascii

    mov ebx, dword ptr [receivedSize]
    sub ebx, 3h
    mov ecx, ebx
    dec edi
    xor ebx, ebx
    mov esi, offset decimalMask
convert_decimal:
    xor eax, eax
    mov edx, dword ptr [esi]
    mov al, byte ptr [edi]
    mul edx
    add ebx, eax
    add esi, 4h
    dec edi
    loop convert_decimal

    push ebx
    push 0h
    push PROCESS_TERMINATE
    call [OpenProcess]
    mov dword ptr [processHandle], eax
    push 0h
    push eax
    call [TerminateProcess]
    jmp receive_comm

run_comm:
	mov ecx, offset [receiveBuffer + 2h]
	mov ebx, dword ptr [receivedSize]
	mov byte ptr [receiveBuffer + ebx - 1h], 00h

	push offset processInformation
	push offset startupInformation
	push 0h
	push 0h
	push 0h
	push 0h
	push 0h
	push 0h
	push 0h
	push ecx
	call [CreateProcessA]
	jmp receive_comm

list: 	; naredba "l "
	push 0h
	push TH32CS_SNAPPROCESS
	call [CreateToolhelp32Snapshot]
	mov dword ptr [snapHandle], eax
	
	mov dword ptr [processEntry], 128h
	push offset processEntry
	push eax
	call [Process32First]

	;u PROCESSENTRY32 tagu, 
	;ProcessID je treci parametar, [tag + 8h]
	;szExeFile[MAX_PATH] je posljednji parametar, na [tag + 24h] nadalje

	;konverzija PID-a iz hex u ascii oblik
	mov eax, dword ptr [processEntry + 8h]	; PID
	mov edi, offset [PID + 3h]

ASCIIConvert:	
	xor edx, edx
	mov ebx, 0Ah
    div ebx								;PID / 10 => eax <- kvocijent, edx <- ostatak
    mov bl, byte ptr [ASCIIlookup + edx]	;bl <- ASCII vrijednost
    mov byte ptr [edi], bl				
    dec edi								;iduca znamenka
    cmp eax, 0							
    jnz ASCIIConvert					;dok rezultat nije 0
    
	mov ecx, 0h
	mov esi, offset [processEntry + 24h]
	mov edi, offset [sendBuffer]
memcopy:
	movsb
	inc ecx
	mov al, byte ptr [esi]
	cmp al, 0h
	jne memcopy

	mov byte ptr [sendBuffer + ecx], 20h

	mov ebx, dword ptr [PID]
    mov dword ptr [PID], 0h 
    mov dword ptr [sendBuffer + ecx + 1h], ebx	;PID

	mov word ptr [sendBuffer + ecx + 5h], 0A0Dh		;pokusaj da se svaki listing ispisuje od pocetka reda, ne znam zasto ne radi
	mov dword ptr [sendBufferCounter], ecx

	push MSG_DONTROUTE
	push 30h
	push offset sendBuffer
	push dword ptr [connectionHandle]
	call [send]
	mov dword ptr [sendSize], eax

	mov ecx, dword ptr [sendBufferCounter]
	add ecx, 7h
	mov esi, offset [sendBuffer]

cleanup:
	mov byte ptr [esi], 0h
	inc esi
	loop cleanup
	jmp empty_snapshot

empty_snapshot:
	mov dword ptr [processEntry], 128h
	push offset processEntry
	push dword ptr [snapHandle]
	call [Process32Next]
	cmp eax, 01h
	jne close_snap_handle

	mov eax, dword ptr [processEntry + 8h]	; PID
	mov edi, offset [PID + 3h]
	jmp ASCIIConvert

close_snap_handle:
	push dword ptr [snapHandle]
	call [CloseHandle]
	jmp receive_comm

epilogue:
	call [WSACleanup]

	push 0h
	call [ExitProcess]




end start