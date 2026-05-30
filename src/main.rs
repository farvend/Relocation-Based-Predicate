use std::arch::asm;


fn main() {
    unsafe {
        asm!(
            "push rax",
            "push rcx",
            // mov eax, 0xDEADC0DE
            ".byte 0xB8, 0xDE, 0xC0, 0xAD, 0xDE",
            // mov ecx, 0xDEADC0DE
            ".byte 0xB9, 0xDE, 0xC0, 0xAD, 0xDE",
            "xor eax, ecx",
            "test eax, eax",
            "pop rcx",
            "pop rax",
            "jnz 2f",
            "jz 3f",
            "3:",
            "ret",
            "2:",
        );
    }

    println!("runnin'");
}