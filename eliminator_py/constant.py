
# Loop threshold
LOOPTHRESHOLD = 15
PATCH_TIME_LIMIT = 20

# Path replacement threshold
PATH_REPLACEMENT_THRESHOLD = 10

#
COND_JUMPS = ['jo','jno','js', 'jns', 'je', 'jne', 'jz', 'jnz',
            'jb', 'jnb', 'jae', 'jnae', 'jc', 'jnc', 'ja', 'jna',
            'jbe', 'jnbe', 'jl', 'jnl', 'jge', 'jnge', 'jg', 'jng',
            'jle', 'jnle', 'jp', 'jnp','jpe', 'jpo', 'jcxz', 'jecxz']

# Eflags
EFLAGS = {
"CF" : 0X0001, # 1: Carry
"PF" : 0X0004, # 1: Even
"AF" : 0x0010,
"ZF" : 0x0040, # 1: zero, 0 not zero
"SF" : 0x0080, # 1: negtive, 0 positive
"TF" : 0x0100,
"IF" : 0x0200,
"DF" : 0x0400,
"OF" : 0x0800  # 1: OV, 0 NV
}

# Data Instructions

COMPARISON_INS = ['cmp', 'test']
DATACHANGE_INS = ['mov', 'add', 'sub', 'mul']
FIRSTARG_OFFSET = 8 # No anti-fuzz strategy for x86 executables

# rule status
RULE_SMALLER =  0b001
RULE_EQUAL   =  0b010
RULE_LARGER  =  0b100
RULE_UNSIGNED  = 0b1000
# 0x001:smaller, 0x010: equal, 0x100: larger, 0x1000 unsigned
# 0x011: <=

# Node status
VISIBLE_CHARS = 0b1
SCANF_BREAK_CHARS = bytes([0,9,10,11,12,13,32,98])

# Difficulty
DIFF_COMP_NUM_1         =      0x10
DIFF_ONE_CRASH_RECOVER  =    0x1000 # Some hard comparisons need to be fixed
DIFF_NO_CRASH_RECOVER   =    0x2000 # The crash path might be unreachable in the original program
DIFF_TEST_CASE_CONFLICT =      0x80 # Almost impossible
DIFF_FIX_TIMEOUT        = 0x1000000 # Very large to make sure other programs will be fixed first before a time out program to be refixed
DIFF_NO_TRANSFORMATION  =     0x100
DIFF_TRANSOFORMATION    =    0xf000 # Input transformation, very difficult
DIFF_KNOWN_FUNC_CALL    =     0x100 # Deserve to explore once
DIFF_UNNOWN_FUNC_CALL   =     0x800 # Might be self-designed compare function
DIFF_SUCCESS_FIX_ONE    =    0x1000 # If one crash in a patched program is fixed, it is likely the others can be fixed

# Input Type
TYPE_STDIN = 0b1
TYPE_PLACEHOLDER_FILE = 0b10
TYPE_SPECIFY_FILE = 0b100


