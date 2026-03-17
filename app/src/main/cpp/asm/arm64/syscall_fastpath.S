.text
.align 2
.global tee_arm64_syscall3
.type tee_arm64_syscall3, %function
tee_arm64_syscall3:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    svc #0
    ret
