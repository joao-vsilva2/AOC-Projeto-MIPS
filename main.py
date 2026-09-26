import json
import sys
import math

# ============================================================================
# TABELAS DE INSTRUÇÕES MIPS
# ============================================================================

R_TYPE_INSTRUCTIONS = {
    0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
    0x24: "and", 0x25: "or", 0x26: "xor", 0x27: "nor",
    0x2A: "slt", 0x2B: "sltu", 0x00: "sll", 0x02: "srl",
    0x03: "sra", 0x04: "sllv", 0x06: "srlv", 0x07: "srav",
    0x08: "jr", 0x09: "jalr", 0x0C: "syscall", 0x0D: "break",
    0x10: "mfhi", 0x11: "mthi", 0x12: "mflo", 0x13: "mtlo",
    0x18: "mult", 0x19: "multu", 0x1A: "div", 0x1B: "divu"
}

I_TYPE_INSTRUCTIONS = {
    0x08: "addi", 0x09: "addiu", 0x0A: "slti", 0x0B: "sltiu",
    0x0C: "andi", 0x0D: "ori", 0x0E: "xori", 0x0F: "lui",
    0x20: "lb", 0x21: "lh", 0x23: "lw", 0x24: "lbu", 0x25: "lhu",
    0x28: "sb", 0x29: "sh", 0x2B: "sw",
    0x04: "beq", 0x05: "bne", 0x06: "blez", 0x07: "bgtz"
}

J_TYPE_INSTRUCTIONS = { 0x02: "j", 0x03: "jal" }

REGIMM_INSTRUCTIONS = { 0: "bltz", 1: "bgez", 16: "bltzal", 17: "bgezal" }

# ============================================================================
# FUNÇÕES DE EXTRAÇÃO DE BITS
# ============================================================================

def extract_bits(instruction, start_bit, num_bits):
    shift_amount = start_bit - num_bits + 1
    return (instruction >> shift_amount) & ((1 << num_bits) - 1)

def extract_opcode(instruction): return extract_bits(instruction, 31, 6)
def extract_rs(instruction): return extract_bits(instruction, 25, 5)
def extract_rt(instruction): return extract_bits(instruction, 20, 5)
def extract_rd(instruction): return extract_bits(instruction, 15, 5)
def extract_shamt(instruction): return extract_bits(instruction, 10, 5)
def extract_funct(instruction): return extract_bits(instruction, 5, 6)
def extract_immediate(instruction): return extract_bits(instruction, 15, 16)
def extract_address(instruction): return extract_bits(instruction, 25, 26)

# ============================================================================
# FUNÇÕES DE DECODIFICAÇÃO (FASE 1)
# ============================================================================

def decode_r_type(instruction):
    rs, rt, rd = extract_rs(instruction), extract_rt(instruction), extract_rd(instruction)
    shamt, funct = extract_shamt(instruction), extract_funct(instruction)
    mnemonic = R_TYPE_INSTRUCTIONS.get(funct, f"unknown_r_{funct}")
    
    if mnemonic in ["jr"]: return f"{mnemonic} ${rs}"
    if mnemonic in ["jalr"]: return f"{mnemonic} ${rd}, ${rs}"
    if mnemonic in ["syscall", "break"]: return mnemonic
    if mnemonic in ["mfhi", "mflo"]: return f"{mnemonic} ${rd}"
    if mnemonic in ["mthi", "mtlo"]: return f"{mnemonic} ${rs}"
    if mnemonic in ["mult", "multu", "div", "divu"]: return f"{mnemonic} ${rs}, ${rt}"
    if mnemonic in ["sll", "srl", "sra"]: return f"{mnemonic} ${rd}, ${rt}, {shamt}"
    if mnemonic in ["sllv", "srlv", "srav"]: return f"{mnemonic} ${rd}, ${rt}, ${rs}"
    return f"{mnemonic} ${rd}, ${rs}, ${rt}"

def decode_i_type(instruction):
    opcode = extract_opcode(instruction)
    rs, rt = extract_rs(instruction), extract_rt(instruction)
    immediate = extract_immediate(instruction)
    mnemonic = I_TYPE_INSTRUCTIONS.get(opcode, f"unknown_i_{opcode}")
    
    imm_signed = immediate - 0x10000 if immediate >= 0x8000 else immediate
    
    if mnemonic in ["beq", "bne", "bgtz", "bltz", "blez", "bgez"]:
        if mnemonic in ["bgtz", "bltz", "blez", "bgez"]:
            return f"{mnemonic} ${rs}, {imm_signed}"
        return f"{mnemonic} ${rs}, ${rt}, {imm_signed}"
    if mnemonic in ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]:
        return f"{mnemonic} ${rt}, {imm_signed}(${rs})"
    if mnemonic == "lui": return f"{mnemonic} ${rt}, {immediate}"
    return f"{mnemonic} ${rt}, ${rs}, {imm_signed}"

def decode_j_type(instruction):
    opcode = extract_opcode(instruction)
    address = extract_address(instruction)
    mnemonic = J_TYPE_INSTRUCTIONS.get(opcode, f"unknown_j_{opcode}")
    return f"{mnemonic} {address}"

def decode_regimm(instruction):
    rs, rt = extract_rs(instruction), extract_rt(instruction)
    immediate = extract_immediate(instruction)
    mnemonic = REGIMM_INSTRUCTIONS.get(rt, f"unknown_regimm_rt{rt}")
    imm_signed = immediate - 0x10000 if immediate >= 0x8000 else immediate
    return f"{mnemonic} ${rs}, {imm_signed}"

def decode_instruction(hex_string):
    instruction = int(hex_string, 16)
    opcode = extract_opcode(instruction)
    if opcode == 0: return decode_r_type(instruction)
    if opcode == 0x01: return decode_regimm(instruction)
    if opcode in J_TYPE_INSTRUCTIONS: return decode_j_type(instruction)
    if opcode in I_TYPE_INSTRUCTIONS: return decode_i_type(instruction)
    return f"unknown_opcode_{opcode}"

# ============================================================================
# BANCO DE REGISTRADORES (FASE 2)
# ============================================================================

class RegisterFile:
    def __init__(self, initial_regs=None):
        self.regs = [0] * 32
        self.pc, self.hi, self.lo = 0, 0, 0
        if initial_regs:
            for name, value in initial_regs.items():
                if name == "$pc" or name == "pc": self.pc = value
                elif name == "$hi" or name == "hi": self.hi = value
                elif name == "$lo" or name == "lo": self.lo = value
                elif name.startswith("$"):
                    try: self.regs[int(name[1:])] = value & 0xFFFFFFFF
                    except ValueError: pass

    def get(self, reg_num):
        return 0 if reg_num == 0 else self.regs[reg_num]

    def set(self, reg_num, value):
        if reg_num == 0: return
        self.regs[reg_num] = value & 0xFFFFFFFF

    def to_signed(self, value):
        val = value & 0xFFFFFFFF
        return val - 0x100000000 if val >= 0x80000000 else val

    def get_snapshot(self):
        snapshot = {}
        for i in range(32):
            if self.regs[i] != 0: snapshot[f"${i}"] = self.regs[i]
        if self.pc != 0: snapshot["$pc"] = self.pc
        if self.hi != 0: snapshot["$hi"] = self.hi
        if self.lo != 0: snapshot["$lo"] = self.lo
        return snapshot

# ============================================================================
# EXECUÇÃO DE INSTRUÇÕES (FASE 2)
# ============================================================================

def execute_r_type(instruction, reg_file):
    rs, rt, rd = extract_rs(instruction), extract_rt(instruction), extract_rd(instruction)
    shamt, funct = extract_shamt(instruction), extract_funct(instruction)
    
    rs_val, rt_val = reg_file.get(rs), reg_file.get(rt)
    rs_s, rt_s = reg_file.to_signed(rs_val), reg_file.to_signed(rt_val)

    if funct == 0x20: reg_file.set(rd, reg_file.to_signed(rs_s + rt_s))       # add
    elif funct == 0x21: reg_file.set(rd, rs_val + rt_val)                     # addu
    elif funct == 0x22: reg_file.set(rd, reg_file.to_signed(rs_s - rt_s))     # sub
    elif funct == 0x23: reg_file.set(rd, rs_val - rt_val)                     # subu
    elif funct == 0x24: reg_file.set(rd, rs_val & rt_val)                     # and
    elif funct == 0x25: reg_file.set(rd, rs_val | rt_val)                     # or
    elif funct == 0x26: reg_file.set(rd, rs_val ^ rt_val)                     # xor
    elif funct == 0x27: reg_file.set(rd, ~(rs_val | rt_val))                  # nor
    elif funct == 0x2A: reg_file.set(rd, 1 if rs_s < rt_s else 0)             # slt
    elif funct == 0x10: reg_file.set(rd, reg_file.hi)                         # mfhi
    elif funct == 0x12: reg_file.set(rd, reg_file.lo)                         # mflo
    elif funct == 0x00: reg_file.set(rd, rt_val << shamt)                     # sll
    elif funct == 0x02: reg_file.set(rd, rt_val >> shamt)                     # srl
    elif funct == 0x03: reg_file.set(rd, reg_file.to_signed(rt_val) >> shamt) # sra
    elif funct == 0x04: reg_file.set(rd, rt_val << rs_val)                    # sllv
    elif funct == 0x06: reg_file.set(rd, rt_val >> rs_val)                    # srlv
    elif funct == 0x07: reg_file.set(rd, reg_file.to_signed(rt_val) >> rs_val)# srav
    elif funct == 0x18: # mult
        prod = rs_s * rt_s
        if prod < 0: prod = prod & 0xFFFFFFFFFFFFFFFF
        reg_file.hi = (prod >> 32) & 0xFFFFFFFF; reg_file.lo = prod & 0xFFFFFFFF
    elif funct == 0x19: # multu
        prod = rs_val * rt_val
        reg_file.hi = (prod >> 32) & 0xFFFFFFFF; reg_file.lo = prod & 0xFFFFFFFF
    elif funct == 0x1A: # div
        if rt_s != 0:
            reg_file.lo = reg_file.to_signed(math.trunc(rs_s / rt_s))
            reg_file.hi = reg_file.to_signed(rs_s - math.trunc(rs_s / rt_s) * rt_s)
    elif funct == 0x1B: # divu
        if rt_val != 0:
            reg_file.lo = rs_val // rt_val; reg_file.hi = rs_val % rt_val

def execute_i_type(instruction, reg_file):
    opcode = extract_opcode(instruction)
    rs, rt = extract_rs(instruction), extract_rt(instruction)
    immediate = extract_immediate(instruction)
    
    rs_val = reg_file.get(rs)
    rs_s = reg_file.to_signed(rs_val)
    imm_s = immediate - 0x10000 if immediate >= 0x8000 else immediate

    if opcode == 0x08: reg_file.set(rt, reg_file.to_signed(rs_s + imm_s))     # addi
    elif opcode == 0x09: reg_file.set(rt, rs_val + (imm_s & 0xFFFFFFFF))      # addiu
    elif opcode == 0x0A: reg_file.set(rt, 1 if rs_s < imm_s else 0)           # slti
    elif opcode == 0x0C: reg_file.set(rt, rs_val & immediate)                 # andi
    elif opcode == 0x0D: reg_file.set(rt, rs_val | immediate)                 # ori
    elif opcode == 0x0E: reg_file.set(rt, rs_val ^ immediate)                 # xori

def execute_instruction(hex_string, reg_file):
    instruction = int(hex_string, 16)
    opcode = extract_opcode(instruction)
    if opcode == 0: execute_r_type(instruction, reg_file)
    elif opcode in I_TYPE_INSTRUCTIONS: execute_i_type(instruction, reg_file)
    # J-type e REGIMM (branches) não alteram registradores aritméticos nesta fase

# ============================================================================
# PROCESSAMENTO PRINCIPAL E I/O
# ============================================================================

def process_mips_simulation(input_data):
    output_data = []
    for program in input_data:
        initial_regs = program.get("config", {}).get("regs", {})
        reg_file = RegisterFile(initial_regs)
        
        for hex_instruction in program.get("text", []):
            assembly_text = decode_instruction(hex_instruction)
            execute_instruction(hex_instruction, reg_file)
            
            output_data.append({
                "hex": hex_instruction,
                "text": assembly_text,
                "regs": reg_file.get_snapshot(),
                "mem": {},
                "stdout": ""
            })
    return output_data

def main():
    if len(sys.argv) != 3:
        print("Uso: python mips_simulator.py <input.json> <output.json>")
        sys.exit(1)
    
    try:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        
        output_data = process_mips_simulation(input_data)
        
        with open(sys.argv[2], 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
            
        print(f"Sucesso! {len(output_data)} instruções processadas.")
    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()