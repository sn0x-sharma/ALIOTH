import random, sys, os

def generate_asm(stub_count=1024):
    base_file = "syscalls_base.asm"
    output_file = "syscalls.asm"
    
    if not os.path.exists(base_file):
        print(f"[!] Error: {base_file} not found.")
        sys.exit(1)
    
    with open(base_file, "r") as f:
        base_content = f.read()
    
    stubs = ""
    for i in range(stub_count):
        stubs += f"    PUBLIC Fnc{i:04X}\n    ALIGN 16\n    Fnc{i:04X} PROC\n"
        stubs += f"        mov eax, {i}\n        jmp SyscallDispatcher\n"
        
        padding_type = random.randint(0, 3)
        if padding_type == 0:
            stubs += "        nop\n" * 6
        elif padding_type == 1:
            stubs += "        xchg r8, r8\n" + "        nop\n" * 3
        elif padding_type == 2:
            stubs += "        xchg ax, ax\n        xchg ax, ax\n" + "        nop\n" * 2
        else:
            stubs += "        nop\n        xchg r8, r8\n        nop\n        xchg r8, r8\n"
        
        stubs += f"    Fnc{i:04X} ENDP\n\n"
    
    stubs += "end\n"
    
    with open(output_file, "w") as f:
        f.write(base_content + "\n" + stubs)
    
    print(f"[+] Generated {stub_count} stubs -> {output_file}")

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
    generate_asm(count)
