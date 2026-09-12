import json
import sys

# Teste de comunicação

# ============================================================================
# TABELAS DE INSTRUÇÕES MIPS
# ============================================================================

# Instruções R-type (opcode = 0)
R_TYPE_INSTRUCTIONS = {
    0x20: "add",    # 32
    0x21: "addu",   # 33
    0x22: "sub",    # 34
    0x23: "subu",   # 35
    0x24: "and",    # 36
    0x25: "or",     # 37
    0x26: "xor",    # 38
    0x27: "nor",    # 39
    0x2A: "slt",    # 42
    0x2B: "sltu",   # 43
    0x00: "sll",    # 0
    0x02: "srl",    # 2
    0x03: "sra",    # 3
    0x04: "sllv",   # 4
    0x06: "srlv",   # 6
    0x07: "srav",   # 7
    0x08: "jr",     # 8
    0x09: "jalr",   # 9
    0x0C: "syscall",# 12
    0x0D: "break",  # 13
    0x10: "mfhi",   # 16
    0x11: "mthi",   # 17
    0x12: "mflo",   # 18
    0x13: "mtlo",   # 19
    0x18: "mult",   # 24
    0x19: "multu",  # 25
    0x1A: "div",    # 26
    0x1B: "divu",   # 27
}

# Instruções I-type (diferenciadas pelo opcode)
I_TYPE_INSTRUCTIONS = {
    0x08: "addi",   # 8
    0x09: "addiu",  # 9
    0x0A: "slti",   # 10
    0x0B: "sltiu",  # 11
    0x0C: "andi",   # 12
    0x0D: "ori",    # 13
    0x0E: "xori",   # 14
    0x0F: "lui",    # 15
    0x20: "lb",     # 32
    0x21: "lh",     # 33
    0x23: "lw",     # 35
    0x24: "lbu",    # 36
    0x25: "lhu",    # 37
    0x28: "sb",     # 40
    0x29: "sh",     # 41
    0x2B: "sw",     # 43
    0x04: "beq",    # 4
    0x05: "bne",    # 5
}

# Instruções J-type (diferenciadas pelo opcode)
J_TYPE_INSTRUCTIONS = {
    0x02: "j",      # 2
    0x03: "jal",    # 3
}


# ============================================================================
# FUNÇÕES DE EXTRAÇÃO DE BITS
# ============================================================================

# Funcionará da seguinte forma:
# 1. Shift à direita para alinhar o campo com a posição 0
# 2. Aplica máscara AND com (2^num_bits - 1) para isolar os bits

def extract_bits(instruction, start_bit, num_bits):

    # instruction: Valor inteiro da instrução (32 bits)
    # start_bit: Bit mais significativo do campo (0-31, onde 31 é o MSB)
    # num_bits: Número de bits a extrair
    
    # Calcula quantos bits shiftar à direita
    shift_amount = start_bit - num_bits + 1
    
    # Shift à direita
    shifted = instruction >> shift_amount
    
    # Cria máscara: (2^num_bits - 1) = todos 1s no tamanho do campo
    mask = (1 << num_bits) - 1
    
    # Aplica máscara para isolar apenas os bits desejados
    return shifted & mask # Valor inteiro do campo extraído


def extract_opcode(instruction):
    # Extrai o opcode (bits 31-26, 6 bits)
    return extract_bits(instruction, 31, 6)


def extract_rs(instruction):
    # Extrai rs - registrador fonte (bits 25-21, 5 bits)
    return extract_bits(instruction, 25, 5)


def extract_rt(instruction):
    # Extrai rt - registrador fonte/destino (bits 20-16, 5 bits)
    return extract_bits(instruction, 20, 5)


def extract_rd(instruction):
    # Extrai rd - registrador destino (bits 15-11, 5 bits)
    return extract_bits(instruction, 15, 5)


def extract_shamt(instruction):
    # Extrai shamt - shift amount (bits 10-6, 5 bits)
    return extract_bits(instruction, 10, 5)


def extract_funct(instruction):
    # Extrai funct - função (bits 5-0, 6 bits)
    return extract_bits(instruction, 5, 6)


def extract_immediate(instruction):
    # Extrai immediate - valor imediato (bits 15-0, 16 bits)
    return extract_bits(instruction, 15, 16)


def extract_address(instruction):
    # Extrai address - endereço (bits 25-0, 26 bits)
    return extract_bits(instruction, 25, 26)


# ============================================================================
# FUNÇÕES DE DECODIFICAÇÃO POR TIPO
# ============================================================================

def decode_r_type(instruction):

    rs = extract_rs(instruction)
    rt = extract_rt(instruction)
    rd = extract_rd(instruction)
    shamt = extract_shamt(instruction)
    funct = extract_funct(instruction)
    
    # Busca o mnemônico na tabela
    mnemonic = R_TYPE_INSTRUCTIONS.get(funct, f"unknown_r_{funct}")
    
    # Formata a instrução assembly de acordo com o tipo
    # Instruções especiais têm formatos diferentes
    if mnemonic in ["jr", "jalr"]:
        # jr $rs | jalr $rd, $rs
        if mnemonic == "jr":
            return f"{mnemonic} ${rs}"
        else:
            return f"{mnemonic} ${rd}, ${rs}"
    
    elif mnemonic in ["syscall", "break"]:
        # syscall | break (sem operandos)
        return mnemonic
    
    elif mnemonic in ["mfhi", "mflo"]:
        # mfhi $rd | mflo $rd
        return f"{mnemonic} ${rd}"
    
    elif mnemonic in ["mthi", "mtlo"]:
        # mthi $rs | mtlo $rs
        return f"{mnemonic} ${rs}"
    
    elif mnemonic in ["mult", "multu", "div", "divu"]:
        # mult $rs, $rt | div $rs, $rt
        return f"{mnemonic} ${rs}, ${rt}"
    
    elif mnemonic in ["sll", "srl", "sra"]:
        # sll $rd, $rt, shamt
        return f"{mnemonic} ${rd}, ${rt}, {shamt}"
    
    elif mnemonic in ["sllv", "srlv", "srav"]:
        # sllv $rd, $rt, $rs
        return f"{mnemonic} ${rd}, ${rt}, ${rs}"
    
    else:
        # Formato padrão R-type: mnemonic $rd, $rs, $rt
        return f"{mnemonic} ${rd}, ${rs}, ${rt}"


def decode_i_type(instruction):

    opcode = extract_opcode(instruction)
    rs = extract_rs(instruction)
    rt = extract_rt(instruction)
    immediate = extract_immediate(instruction)
    
    # Busca o mnemônico na tabela
    mnemonic = I_TYPE_INSTRUCTIONS.get(opcode, f"unknown_i_{opcode}")
    
    # Formata a instrução assembly de acordo com o tipo
    if mnemonic in ["beq", "bne"]:
        # beq $rs, $rt, offset | bne $rs, $rt, offset
        # O offset é um valor signed de 16 bits
        if immediate >= 0x8000:
            immediate = immediate - 0x10000  # Converte para signed
        return f"{mnemonic} ${rs}, ${rt}, {immediate}"
    
    elif mnemonic in ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"]:
        # lw $rt, offset($rs)
        if immediate >= 0x8000:
            immediate = immediate - 0x10000  # Converte para signed
        return f"{mnemonic} ${rt}, {immediate}(${rs})"
    
    elif mnemonic == "lui":
        # lui $rt, immediate
        return f"{mnemonic} ${rt}, {immediate}"
    
    else:
        # Formato padrão I-type: mnemonic $rt, $rs, immediate
        if immediate >= 0x8000:
            immediate = immediate - 0x10000  # Converte para signed
        return f"{mnemonic} ${rt}, ${rs}, {immediate}"


def decode_j_type(instruction):

    opcode = extract_opcode(instruction)
    address = extract_address(instruction)
    
    # Busca o mnemônico na tabela
    mnemonic = J_TYPE_INSTRUCTIONS.get(opcode, f"unknown_j_{opcode}")
    
    # Formato: j address | jal address
    return f"{mnemonic} {address}"


# ============================================================================
# FUNÇÃO PRINCIPAL DE DECODIFICAÇÃO
# ============================================================================

# Decodifica uma instrução MIPS de hexadecimal para assembly
def decode_instruction(hex_string):
    # hex_string: String hexadecimal da instrução (ex: "0x02114020")
    
    # Converte hexadecimal para inteiro
    instruction = int(hex_string, 16)
    
    # Extrai o opcode para determinar o tipo
    opcode = extract_opcode(instruction)
    
    # Decodifica de acordo com o tipo
    if opcode == 0:
        # R-type: opcode é 0, diferenciado pelo funct
        return decode_r_type(instruction)
    elif opcode in J_TYPE_INSTRUCTIONS:
        # J-type
        return decode_j_type(instruction)
    elif opcode in I_TYPE_INSTRUCTIONS:
        # I-type
        return decode_i_type(instruction)
    else:
        # Instrução não reconhecida
        return f"unknown_opcode_{opcode}"


# ============================================================================
# FUNÇÕES DE LEITURA E ESCRITA DE JSON
# ============================================================================

def read_input_json(filename):
    # Lê o arquivo JSON de entrada.
    
    with open(filename, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_output_json(output_data, filename):
    # Escreve o arquivo JSON de saída.
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)


# ============================================================================
# FUNÇÃO PRINCIPAL DE PROCESSAMENTO
# ============================================================================

def process_mips_simulation(input_data):
    # Processa a simulação MIPS - Apenas decodificação.
    # input_data: Lista de objetos JSON de entrada
    
    output_data = []
    
    for program in input_data:
        # Extrai o array de instruções
        text_instructions = program.get("text", [])
        
        # Processa cada instrução
        for hex_instruction in text_instructions:
            # Decodifica a instrução
            assembly_text = decode_instruction(hex_instruction)
            
            # Cria o objeto de saída
            output_entry = {
                "hex": hex_instruction,
                "text": assembly_text,
                "regs": {},      # Fase 1: vazio
                "mem": {},       # Fase 1: vazio
                "stdout": ""     # Fase 1: string vazia
            }
            
            output_data.append(output_entry)
    
    return output_data # Lista de objetos JSON de saída


# ============================================================================
# FUNÇÃO MAIN
# ============================================================================

def main():

    # Verifica argumentos da linha de comando
    if len(sys.argv) != 3:
        print("Uso: python mips_simulator.py <input.json> <output.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        # Lê o JSON de entrada
        print(f"Lendo arquivo de entrada: {input_file}")
        input_data = read_input_json(input_file)
        
        # Processa a simulação
        print("Processando decodificação de instruções...")
        output_data = process_mips_simulation(input_data)
        
        # Escreve o JSON de saída
        print(f"Escrevendo arquivo de saída: {output_file}")
        write_output_json(output_data, output_file)
        
        print("Processamento concluído com sucesso!")
        
        # Imprime resumo
        print(f"\nResumo:")
        print(f"  Total de instruções processadas: {len(output_data)}")
        
        # Teste de validação
        if output_data:
            print(f"\nPrimeira instrução decodificada:")
            print(f"  Hex: {output_data[0]['hex']}")
            print(f"  Assembly: {output_data[0]['text']}")
        
    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Erro ao decodificar JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Erro inesperado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()