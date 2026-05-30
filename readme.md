# Relocation-Based Predicate

An anti-static-analysis technique that abuses the PE relocation table to create opaque predicates invisible to static analysis tools and symbolic execution engines.

*Note: The current implementation works on x64, but the core technique is also achievable on x86/x32.*

**This is a proof of concept, not a complete, production-ready tool.**

**Example binary is available in Releases**

## Screenshots

Binary Ninja:
<img width="689" height="240" alt="изображение" src="https://github.com/user-attachments/assets/93b7811d-6d6c-4a50-bada-dd6cc0537756" />
x64dbg:
<img width="511" height="78" alt="изображение" src="https://github.com/user-attachments/assets/615b38eb-eb6e-4f1f-91d5-bf546de8c788" />

## The Idea

Static analyzers (IDA Pro, Binary Ninja, Ghidra) parse PE files **as they are on disk**. But the Windows PE Loader **modifies values in memory** before execution when applying relocations (ASLR fixes, vtables, IAT, global pointers, etc.).

Consider this assembly:
```asm
mov     eax, 0xDEADC0DE
mov     ecx, 0xDEADC0DE
xor     eax, ecx
test    eax, eax
jne     real_path

je      dead_path
```

Static analysis concludes that `eax XOR ecx = 0` and assumes that the `dead_path` will always be executed. However, if we apply a relocation that patches the immediate operand of the first `mov`, its value will be changed at load time. The `xor` will then produce a non-zero result, and `real_path` will be taken instead.

## Details of Current Implementation

Even though many relocation types exist in x64 PE files, the most popular and standard one is `IMAGE_REL_BASED_DIR64` (0xA), which patches an 8-byte (64-bit) absolute pointer. 

You might have noticed that in the previous example I used 32-bit registers and values (`eax`, `imm32`). Applying a 64-bit relocation over a 32-bit instruction would normally corrupt the surrounding opcodes. However, I came up with a neat trick that allows using `IMAGE_REL_BASED_DIR64` safely on 32-bit values:

By setting the linker base address to `0x10000` (the minimum possible value for a valid Windows PE executable), the ASLR delta (`actual_load_address - ImageBase`) is guaranteed to be **non-negative**. Windows cannot map a user-space image below `0x10000`, so no subtraction ever occurs, avoiding borrow/underflow issues.

On x64 Windows, user-space virtual addresses occupy only 47 bits (`0x0` to `0x7FFFFFFFFFFF`). Thus, the upper 17 bits are always zero. Additionally, image bases are always aligned to a `0x10000` (64 KB) boundary, meaning the lower 16 bits of the ASLR delta will also always be zero.

In memory (little-endian), this 8-byte relocation delta looks like this:

```
Byte:  [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]
        00   00   XX   XX   XX   XX   00   00
        -------   -----------------   -------
   always zero     only these change  always zero
   (page align)                       (47-bit user-space)
```

As a result, **only bytes 2–5 are ever modified** by the addition — which perfectly matches a 32-bit size. This means a 64-bit relocation (`IMAGE_REL_BASED_DIR64`) can safely overlap a 32-bit instruction operand without destroying the surrounding bytes.

## How it is Achieved

The Windows OS Loader applies relocations to ANY section regardless of its memory protection rights (Write, Execute, or Read). Therefore, we can safely point a relocation directly into the `.text` (code) section. 

We write inline assembly with a primitive opaque predicate:

```asm
push rax
push rcx
; 1-byte opcode (B8) + 4-byte imm32
mov eax, 0xDEADC0DE 
mov ecx, 0xDEADC0DE  
xor eax, ecx
test eax, eax
pop rcx
pop rax
jnz 2f      ; Real code (always taken at runtime)
jz 3f       ; Dead branch (static analyzers go here)
3:
ret
2:
...
```

To make the trick work, the `IMAGE_REL_BASED_DIR64` entry is created at `address_of_imm32 - 2`. Because of our delta bitmask (`00 00 XX XX XX XX 00 00`), the first two `00 00` bytes of the addition safely overlay the `mov eax` opcode (`0xB8`) and the preceding instruction byte, modifying nothing, while the `XX` bytes fall perfectly onto `0xDEADC0DE`.

## Why is this cool

Abusing relocations for obfuscation isn't a completely new concept. In the past, malware and packers used the relocation table as a decryption engine to unpack code. However, those techniques died out because they required a predictable base address. Once Microsoft enforced ASLR and killed the ability to manipulate load addresses reliably, those decryption engines broke.

My approach does the exact opposite: instead of fighting ASLR, it abuses it. I don't care what the actual delta is, as long as the ASLR randomization produces a non-zero delta.

On top of that, standard opaque predicates rely on math formulas that modern deobfuscators and symbolic execution engines (like Z3 or angr) can easily solve. But since this predicate is resolved mathematically by the Windows Loader before the CPU even executes the first instruction, automated analysis tools are completely blind to it.

As an extra bonus, IDA doesn't visually mark these relocated bytes in its disassembly at all, thanks to our `IMAGE_REL_BASED_DIR64` on a 32-bit operand trick.
