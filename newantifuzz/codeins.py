import re, random, string, os, sys, time

CODE_SEG_LEN = 100

TOPN_FREQUENT_FUNCS= 10
INIT_FUNC_NAME = 'ATinit'
COUNTER_NAME = 'ab_count'
FUNC_BUF_NAME = 'funcs_buf'
FUNC_PTR_NAME = 'funcs'
INDEX_NAME = 'funcs_idx'
FUNC_PTR_TYPE_SUFFIX = 'ptr'
INTERMEDIATE_IDENT = 'itm'
REPATED_INS = 'nop'
LANDING_LEN = 1500
MAXIMUM_OVERLOAD_VALUE = 255 # Better no more than 1000
VARMAPPING_BIT = 6

def get_random_string(length_limit):
    # At least four bytes for randomness
    length = random.randint(4, length_limit)
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str
def make_pattern(s):
    s = s.replace("\\", "\\\\").replace("*", "\\*").replace("(", "\\(").replace(")", "\\)").replace(".", "\\.").replace("+", '\\+').replace("[", '\\[').replace("]", '\\]').replace("?", "\\?").replace("/", '\\/').replace("|", '\\|')
    # Replace spaces with \s
    s = ' '.join(s.split())
    s = s.replace(" ", '\\s*')
    return s

def make_typedef(func_name, l):

    ret_type = l[0]
    var_type = l[1:]
    var_type = ','.join(var_type)
    os. sys
    template = 'typedef {0} (*{1}'+FUNC_PTR_TYPE_SUFFIX+') ({2});'
    return template.format(ret_type, func_name, var_type)

def check_if_constvar(var_name):
    allow_chars = string.ascii_uppercase + "_" + string.digits
    for ch in var_name:
        if ch not in allow_chars:
            return False
    return True

def check_nested(operand):
    stack = 0
    for ch in operand:
        if ch == '(':
            stack += 1
        if ch == ")":
            stack -= 1
    if stack != 0:
        return True
    return False


class Antifuzz:
    # Antifuzz for C

    def __init__(self, sources, funcchain = True, daemon_process = True, constrans = True, landingspace=True, instru_detect=True):
        self.sources = sources
        self.funcchain = landingspace
        self.constrans = constrans
        self.landingspace = landingspace
        self.instru_detect = instru_detect
        self.daemon_process = daemon_process
        # To use landingspace, must use funcchain for functions containing jump instructions
        if self.landingspace:
            self.funcchain = True
        # self.funcPattern = r"(\w+\s*[\*,&]*)\s+(\w+)\s*\(([^,{})]*),([^,{})]*)\)"

        self.commonFuncs = ['bool', 'int', 'char', 'void', 'float', 'long', 'double', 'wchar_t']
        self.userDefinedTypes = ['bfd_boolean', 'Filedata']
        self.noHandleCmpsOperands = ['NULL', '0', '-1', '1']
        self.funcsList = []
        self.funcCallCnt = {}
        self.toTransFunc = {}
        self.funcPtr = {}
        self.fakecodes = {}
        self.ori_itm_funcs = {}
        self.def_codes = '''
#include<stdlib.h>
#include<time.h>
'''
        self.available_opcodes = {'nop': '0x90',  'cmc': '0xf5', 'clc': '0xf8', 'stc': '0xf9', 'add  ${0}, %al': '0x04', 'adc ${0},%al':'0x14', 'and ${0}, %al':'0x24', 'xor ${0}, %al': '0x34'}

        self.opcode_check = {'nop': '0x90',  'cmc': '0xf5', 'clc': '0xf8', 'stc': '0xf9', 'cli':'0xfa', 'sti':'0xfb', 'add': '0x04', 'adc':'0x14', 'and':'0x24', 'xor': '0x34',
'jmp':'0xeb'}

        if self.instru_detect:
            self.detect_codes = '''
#include<stdlib.h>
#include<time.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

#define abs(x) ((a>0)?(a):(-a))

unsigned long long atfz_t2, atfz_t1;

void in_loop(){ int a=0, b=1, i; for (i =0 ; i < 1000; i++)a+=b; return;}

uint64_t inline rdtsc(){
    unsigned int lo,hi;
    __asm__ ("CPUID");
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}


void delay(void)
{
  fd_set set;
  struct timeval timeout;
  int rv;
  char buff[100];
  int len = 90;
  int stdinput = dup(STDIN_FILENO);
  int filedesc = open(stdinput, O_WRONLY);

  FD_ZERO(&set); /* clear the set */
  //FD_SET(filedesc, &set); /* add our file descriptor to the set */

  timeout.tv_sec = 1;
  timeout.tv_usec = 0;

  rv = select(filedesc + 1, &set, NULL, NULL, &timeout);
  
  if(rv == -1)
    perror("select"); /* an error accured */
  else if(rv == 0)
    printf("timeout"); /* a timeout occured */
  else
    read( filedesc, buff, len ); /* there was data to read */
  close(filedesc);
}

void anti_fuzz(){
    // direct delay, can be replaced by a series of calculations or even abort/block the program
    delay();
}

void detect() {
    unsigned long long t2 , t1, t3, t4;
    unsigned long long diff1, diff2;   
    
    t3 = rdtsc () ;  
    in_loop();
    t4 = rdtsc () ;
   
    t1 = rdtsc () ;
    int a=0, b=1, i;
    for (i =0 ; i < 1000; i++)a+=b;
    t2 = rdtsc () ;
    
    diff1 =  (t2-t1);
    diff2 =  (t4-t3);  

    double perc = (double)(diff2)/(diff1) * 100;
    printf("%llu, %llu, %llu, %llu\\n", t1, t2, t3, t4);
    printf("%llu, %llu, %lf\\n", diff2, diff1, perc);
    if (perc > 130) anti_fuzz();
}

'''
        if self.daemon_process:
            self.daemon_process_codes = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define ERR_EXIT(m) \
do\
{\
    perror(m);\
    exit(EXIT_FAILURE);\
}\
while (0);\

#define START_FD 1000
#define ATFZ_ALERT_NUM 60
#define PATROL_TIME 30
#define ATFZ_PREFIX ("/tmp/.atfz_deamon")

void creat_daemon(void)
{
 
    pid_t pid;
    pid = fork();
   
    if( pid == -1)
        ERR_EXIT("fork error");
    if(pid == 0 )
    {
        if(setsid() == -1)
            ERR_EXIT("SETSID ERROR");
        umask(0);

        int atfz_cnt = 1;
        char atfz_file[30], dest_file[30];
        FILE *fp;

        sprintf(dest_file, "%s%d", ATFZ_PREFIX, ATFZ_ALERT_NUM);
        fp = fopen(dest_file, "r");

        if (fp)
            exit(EXIT_SUCCESS);

        while (atfz_cnt <= ATFZ_ALERT_NUM){
            sprintf(atfz_file, "%s%d", ATFZ_PREFIX, atfz_cnt);
            fp = fopen(atfz_file, "r");
            if (!fp){
                break;
            }
            atfz_cnt++;
        }

        sprintf(atfz_file, "%s%d", ATFZ_PREFIX, atfz_cnt);

        fp = fopen(atfz_file, "w");

        sleep(PATROL_TIME);

        fclose(fp);

        printf("%s\\n", atfz_file);

        if (atfz_cnt < ATFZ_ALERT_NUM)
            remove(atfz_file);

        exit(EXIT_SUCCESS);
    }
  
    return;

}

'''

    def gen_ins(self, length, func_name):
        random.seed(time.time())
        ins_list = list(self.available_opcodes.keys())
        land_sp = []
        
        for i in range(length-1):
            pos = random.randint(0, len(ins_list)-1)
            ins = ins_list[pos]
            opcode = self.available_opcodes[ins]
            land_sp.append(ins)
        pos = random.randint(0, len(ins_list)-5)
        ins = ins_list[pos]
        opcode = self.available_opcodes[ins]
        land_sp.append(ins)
        #print(land_sp)

        # insert jump
        i = 0
        while (i < length-1):
            if "xor" in land_sp[i+1] or "and" in land_sp[i+1] or "adc" in land_sp[i+1]:
                next_opcode = int(self.opcode_check[land_sp[i+1][:3]], 16)
                #print(next_opcode)
                if (next_opcode + i +2 < length):
                    land_sp[i] = "jmp {0}+{1}".format(func_name, i+next_opcode+2)
                    if (i>0) and "and" in land_sp[i-1] or "xor" in land_sp[i-1] or "adc" in land_sp[i-1] or "add" in land_sp[i-1]:
                        pos = random.randint(0, len(ins_list)-5)
                        ins = ins_list[pos]
                        land_sp[i-1] = ins
                    #i+=jump_gap
                    i = next_opcode + i + 1
            i+= 1
            
        for i in range(length-1):
            if "{0}" in land_sp[i]:
                #print(land_sp[i])
                land_sp[i] = land_sp[i].format(self.opcode_check[land_sp[i+1][:3]])
        i = 0
        while(i < len(land_sp)-1):
            if "jmp" in land_sp[i] or "adc" in land_sp[i] or "add" in land_sp[i] or "and" in land_sp[i] or "xor" in land_sp[i]:
                land_sp = land_sp[:i+1] + land_sp[i+2:]
            i+= 1
        asb_codes = ('\\n'.join(land_sp) + "\\n")
        
        return asb_codes


    def genFakeFunc(self, func_type, argu, func_name, func_number):

        intermidiate_junk_template = '''
extern {0} {1} ({2}) __attribute__((used));
extern {0} {1} ({2});
__asm__ (
"{1}:\\n"
"  {4}"
"  jmp {3}\\n"
);
'''
        if self.landingspace:
            fake_func_ret_template = '''
{0} {1}({2}) __attribute__((used));
{0} {1}({2}){{
    {7}
    int {3} = '''+INDEX_NAME+'''['''+COUNTER_NAME+'''++];
    {8} {4} = (({6})('''+FUNC_PTR_NAME+'''[{3}]+rand()%'''+str(LANDING_LEN+1)+'''))({5});
    return {4};
    
}}
'''

            fake_func_void_template = ''' 
void {0}({1}) __attribute__((used));
void {0}({1}){{
    {5}
    int {2} = '''+INDEX_NAME+'''['''+COUNTER_NAME+'''++];
    (({4})('''+FUNC_PTR_NAME+'''[{2}]+rand()%'''+str(LANDING_LEN+1)+'''))({3});
    return;
    
}}
'''
        else:
            fake_func_ret_template = '''
{0} {1}({2}) __attribute__((used));
{0} {1}({2}){{
    {7}
    int {3} = '''+INDEX_NAME+'''['''+COUNTER_NAME+'''++];
    {8} {4} = (({6})('''+FUNC_PTR_NAME+'''[{3}]))({5});
    return {4};
    
}}
'''

            fake_func_void_template = ''' 
void {0}({1}) __attribute__((used));
void {0}({1}){{
    {5}
    int {2} = '''+INDEX_NAME+'''['''+COUNTER_NAME+'''++];
    (({4})('''+FUNC_PTR_NAME+'''[{2}]))({3});
    return;
}}
'''

        argu_list = argu.split(',')
        var_list = []
        idx_name = get_random_string(5)

        self.funcPtr[func_name] = [func_type]
        for i in range(len(argu_list)):
            # No need to care about pointer

            tmp = argu_list[i].replace("register ", "").replace("const ", '').replace("ATTRIBUTE_UNUSED", '').strip().replace("*", '').replace("unsigned", '').replace("signed",'').replace("[]", '').split()
            tmp = [j for j in tmp if j != '']

            # Ignore arguments with function pointers
            if len(tmp) >= 3:
                del self.funcPtr[func_name]
                if self.landingspace:
                    return None, None, None, None
                else:
                    return None, None, None

            if len(tmp) > 1:
                var = tmp[1]
                if func_name == 'map_over_members':
                    print(tmp)
                var_list.append(var)
                rev_argu = argu_list[i][::-1]
                var_type = rev_argu.replace(var[::-1], '', 1).strip()[::-1]
                self.funcPtr[func_name].append(var_type)

        vars = ','.join(var_list)
        code_seg = ''
        # fake_func_name = get_random_string(5)
        fake_func_name = func_name
        fake_key_seg = ''

        for i in range(func_number):
            if func_type.lower() == 'void':
                if self.landingspace:
                    itm_func = intermidiate_junk_template.format('void', fake_func_name+INTERMEDIATE_IDENT+str(i), argu, fake_func_name + str(i), self.gen_ins(LANDING_LEN, fake_func_name+INTERMEDIATE_IDENT+str(i)))
                fake_func = fake_func_void_template.format(fake_func_name + str(i), argu, idx_name, vars, func_name+FUNC_PTR_TYPE_SUFFIX, '')
                fake_key_seg = fake_func.strip('\n').split("\n")
                fake_key_seg = [j for j in fake_key_seg if j.strip() != '']
                fake_key_seg = fake_key_seg[1:3]
            else:
                if self.landingspace:
                    itm_func = intermidiate_junk_template.format(func_type, fake_func_name+INTERMEDIATE_IDENT+str(i), argu, fake_func_name + str(i), self.gen_ins(LANDING_LEN, fake_func_name+INTERMEDIATE_IDENT+str(i)))
                ret_name = get_random_string(10)
                rettype = func_type.strip()
                if rettype.startswith("local "):
                    rettype = rettype[6:]
                
                fake_func = fake_func_ret_template.format(func_type, fake_func_name+str(i), argu, idx_name, ret_name, vars, func_name+FUNC_PTR_TYPE_SUFFIX, '', rettype)
                
                fake_key_seg = fake_func.strip('\n').strip().split("\n")
                fake_key_seg = [j for j in fake_key_seg if j.strip() != '']
                fake_key_seg = fake_key_seg[1:3]
            
            code_seg += fake_func
            if self.landingspace:
                code_seg += itm_func

        if func_type.lower() == 'void':
            init_func = fake_func_void_template.format(fake_func_name+INIT_FUNC_NAME, argu, idx_name, vars, func_name + FUNC_PTR_TYPE_SUFFIX, COUNTER_NAME + ' = 0;\n'+FUNC_PTR_NAME+' = %s;')
            init_func += "\nvoid {0}({1}) __attribute__((used));\n".format(fake_func_name, argu)
        else:
            ret_name = get_random_string(10)
            rettype = func_type.strip()
            if rettype.startswith("local "):
                rettype = rettype[6:]
            
            init_func = fake_func_ret_template.format(func_type, fake_func_name+INIT_FUNC_NAME, argu, idx_name, ret_name, vars, func_name + FUNC_PTR_TYPE_SUFFIX, COUNTER_NAME + ' = 0;\n'+FUNC_PTR_NAME+' = %s;', rettype)
            init_func += "\n{0} {1}({2}) __attribute__((used));\n".format(func_type, fake_func_name, argu)

        if self.landingspace:
            origin_itm_func = intermidiate_junk_template.format(func_type, fake_func_name+INTERMEDIATE_IDENT, argu, fake_func_name, self.gen_ins(LANDING_LEN, fake_func_name+INTERMEDIATE_IDENT))
            return code_seg, fake_key_seg, init_func, origin_itm_func
        else:
            return code_seg, fake_key_seg, init_func


    def locateFuncBlk(self, search_pattern, codes):
        start = -1
        end = -1
        stack = 1

        res = re.search(search_pattern, codes)

        start_def, end_def = res.span()

        # In case codes[end_def] == "{"
        while codes[end_def] != ")":
            end_def -= 1

        for idx in range(end_def, len(codes)):
            # Main start
            if codes[idx] == '{':
                start = idx
                break

        for idx in range(start+1, len(codes)):
            if codes[idx] == '{':
                stack += 1
            if codes[idx] == '}':
                stack -= 1
            if stack == 0:
                end = idx
                break

        return (start, end, start_def)


    def funcsIdentify(self):
        '''
        Functions in main, and 10 highest frequent used functions.
        '''

        content = ''
        main_codes = ''
        pages = []
        for source in self.sources:
            with open(source, "r") as f:
                tmp = f.read()
                content += tmp
                pages.append(len(tmp))

        self.content = content

        # Search for high appearance functions

        pattern = r"(\w+\s*[\*,&]*)\s+(\w+)\s*\(([^;]*?)\)\s*{"
        #print(pattern)
        funcs = re.findall(pattern , content)
        
        

        for func in funcs:
            tmp = func[0].strip().strip("*").strip()
            print(tmp, func[1])
            if tmp in self.commonFuncs or tmp in self.userDefinedTypes:
                #print(func)
                self.funcsList.append(func)

        for func in self.funcsList:
            func_type = func[0]
            func_name = func[1]
            func_argument = func[2]
            
            #print(func_name)
            # Find main function
            if func_name == 'main':
                search_pattern ="%s\s*main\s*\(([^;]*?)\)"%(func_type)
                start, end, _ = self.locateFuncBlk(search_pattern, content)
                main_codes = content[start:end + 1]

            pattern = r"[^\w]%s\s*\(([^;]*?)\)"%(func_name)
            func_calls = re.findall(pattern, content)

            cnt = 0
            for call in func_calls:
                if func_argument in call:
                    continue
                cnt += 1

            if cnt > 0:
                self.funcCallCnt[func_name] = (cnt, func_type, func_argument)

        fremap = sorted(self.funcCallCnt.items(), key=lambda x:x[1][0],
                        reverse=True)
        fremap = fremap[:TOPN_FREQUENT_FUNCS]

        for func_name, info in fremap:
            func_type = info[1]
            func_argument = info[2]
            if func_name == "main":
                continue
            self.toTransFunc[func_name] = (func_type, func_argument)

        del self.funcsList

        # Search for functions inside main function

        if main_codes == '':
            raise RuntimeError("Cannot locate main function block")

        for func_name, info in self.funcCallCnt.items():
            func_type = info[1]
            func_argument = info[2]

            #print(func_name)
            pattern = r"[^\w]%s\s*\(([^;]*?)\)" % (func_name)
            func_calls = re.findall(pattern, main_codes)

            if len(func_calls) > 0:
                self.toTransFunc[func_name] = (func_type, func_argument)

        #print(self.toTransFunc)

    def funcTrans(self):
        '''
        int ab_count = 0;
        int index[CODE_SEG_LEN] = {};
        void** funcs;

        void cal_idx()
	{
	    int i,j;
		for (i = 0; i < 1000; i++)index[i] = i;
	    for (i = 999; i > 0; i--){
		j = rand()%(i+1);
		swap(index[i], index[j]);
		}

	}

        // Replace function call with

        ab_count = 0;
        int idx = index[ab_count++];

        ret = ((fp)funcs[idx])(argu);
        return ret
        '''
        earliest_fake_code = 99999999999999999
        self.earliest_func = ''

        # if len(self.toTransFunc) == 0:
        #     print("No functions identified")
        #     return

        # Find function definitions, add fake path to definitions, and create their fake copies

        init_funcs = {}
        for func_name, func_info in self.toTransFunc.items():
            if 'digest_check' == func_name:
                continue
            print("#####", func_name)
            func_type = func_info[0]
            ori_func_argument = func_info[1]
            # Remove some control symbols for a better view
            func_argument = ori_func_argument.strip().replace("\t", '').replace("\n", '').replace("  ", " ")
            if self.landingspace:
                added_code_seg, ins_code_seg, init_func, origin_itm_func = self.genFakeFunc(func_type, func_argument, func_name, CODE_SEG_LEN-1)
            else:
                added_code_seg, ins_code_seg, init_func = self.genFakeFunc(func_type, func_argument, func_name, CODE_SEG_LEN-1)
            
            if added_code_seg is None:
                continue 

            self.fakecodes[func_name] = ''
            self.ori_itm_funcs[func_name] = ''
            if self.landingspace:
                self.ori_itm_funcs[func_name] = origin_itm_func
            init_funcs[func_name] = init_func
            func_type = make_pattern(func_type)
            ori_func_argument = make_pattern(ori_func_argument)

            # Match '{' avoid matching a declaration
            search_pattern = "{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name, ori_func_argument)

            start, end, _ = self.locateFuncBlk(search_pattern, self.content)
            func_code = self.content[start:end+1]

            # TODO random insert a line
            # func_code = func_code.split(";")
            # print(func_code)
            # ins_line = random.randint(1, len(func_code)-2)

            ins_pos = -1
            for j in range(len(func_code)):
                if func_code[j] == '{':
                    ins_pos = j
                    break

            if ins_pos == -1:
                raise RuntimeError("Not find function start")

            ins_code_seg = '\n'.join(ins_code_seg) + '}'
            pre = func_code[:ins_pos+1]
            next = func_code[ins_pos+1:]
            func_code = pre + ins_code_seg + next
            #print(func_code)
            #if self.funcchain:
            #    self.content = self.content[:start]+func_code+self.content[end+1:]
            
            self.fakecodes[func_name] += added_code_seg
            
        cal_idx = '''
void swap(int *a, int *b)
{{
    int temp = *a;
    *a = *b;
    *b = temp;
}}

static void **''' + FUNC_PTR_NAME + ''';
static int ''' + COUNTER_NAME + ''' = 0;
static int ''' + INDEX_NAME + '''[{0}] = {{}};
static void (*''' + FUNC_BUF_NAME + '''[''' + str(CODE_SEG_LEN * len(self.funcPtr)) + ''']) = {{}};
void cal_idx()
{{
    int i,j;
    for (i = 0; i < {0}; i++)'''+INDEX_NAME+'''[i] = i;
    for (i = {0} - 1; i > 0; i--){{
        j = rand() % (i+1);
        swap(&'''+INDEX_NAME+'''[i], &'''+INDEX_NAME+'''[j]);
    }}
}}
'''
        if self.funcchain:
            self.def_codes += cal_idx.format(CODE_SEG_LEN)

        funcs_list = []
        funcs_pos = {}
        cnt = 0
        # Function pointers type defs
        for func_name, l in self.funcPtr.items():
            self.fakecodes[func_name] = make_typedef(func_name, l) + '\n' + self.fakecodes[func_name]
            real_func_pos = random.randint(0, CODE_SEG_LEN)
            if self.landingspace:
                tmp_list = [func_name+INTERMEDIATE_IDENT+str(id) for id in range(CODE_SEG_LEN-1)]
                tmp_list = tmp_list[:real_func_pos] + [func_name+INTERMEDIATE_IDENT] + tmp_list[real_func_pos:]
            else:
                tmp_list = [func_name+str(id) for id in range(CODE_SEG_LEN-1)]
                tmp_list = tmp_list[:real_func_pos] + [func_name] + tmp_list[real_func_pos:]
            funcs_list += tmp_list
            funcs_pos[func_name] = cnt
            cnt += 1

        # Function list fill addresses of functions
        fill_funcs_codes = ''
        if self.funcchain:
            func_assignment = FUNC_BUF_NAME+'[{0}] = {1};'
            fill_funcs_codes += "\ntime_t timestamp;\nsrand((unsigned) time(&timestamp));\ncal_idx();\n"
            for i in range(len(funcs_list)):
                fill_funcs_codes += func_assignment.format(i, funcs_list[i])
            
        # Function calls initialization
        for func_name,l in self.funcPtr.items():
            if self.landingspace:
                tmp = init_funcs[func_name].replace("rand()%", "rand()%%")
            else:
                tmp = init_funcs[func_name]
            self.fakecodes[func_name] += tmp%('&'+FUNC_BUF_NAME+'[{0}]'.format(funcs_pos[func_name]*CODE_SEG_LEN))

        if self.funcchain:
        # Replace function calls with init functions
            for func_name in self.funcPtr.keys():
                func_argument = self.toTransFunc[func_name][1]
                pattern = r"[^\w]%s\s*\(([^;]*?)\)\s*" % (func_name)
                search_start = 0
                res = re.search(pattern, self.content[search_start:])
                
                while res is not None:
                    
                    found_call = res.group()
                    call_start, new_start = res.span()
                    call_start += search_start
                    new_start += search_start
                    
                    if "," in func_argument:
                        func_argument = func_argument.split(",")[0]
                    func_argument = func_argument.replace("ATTRIBUTE_UNUSED", "").strip()
                    if "*" in func_argument or " " in func_argument:
                        for tl in range(len(func_argument)-1, 0, -1):
                            if func_argument[tl] == "*" or func_argument[tl] == ' ':
                                func_argument = func_argument[:tl+1]
                                break
                        
                    if re.search(make_pattern(func_argument), found_call) is not None:
                        search_start = new_start
                    else:
                        self.content = self.content[:call_start] + self.content[call_start:new_start].replace(func_name, func_name+INIT_FUNC_NAME, 1) +  self.content[new_start:]

                    res = re.search(pattern, self.content[search_start:])


        # Add fake function copies and initialization
        for func_name in self.funcPtr.keys():
            ori_func_type = self.toTransFunc[func_name][0]
            func_argument = self.toTransFunc[func_name][1]
            func_type = make_pattern(ori_func_type)
            func_argument = make_pattern(func_argument)

            with open("tmp.c", "w") as f:
                f.write(self.content)
            # Match '{' avoid matching a declaration
            search_pattern = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*local\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name, func_argument)
            _, func_end, start_def = self.locateFuncBlk(search_pattern, self.content)

            function_def = self.content[start_def:_]
            res = re.search(func_type, function_def)
            func_pos, _ = res.span()
            constraints = function_def[:func_pos].strip()
            # Add constraints
            
            self.ori_itm_funcs[func_name] = self.ori_itm_funcs[func_name].replace(ori_func_type+" "+func_name, constraints+" "+ori_func_type+" "+func_name)
            self.fakecodes[func_name] = self.fakecodes[func_name].replace(ori_func_type+" "+func_name, constraints+" "+ori_func_type+" "+func_name)
                       

            if earliest_fake_code > start_def:
                earliest_fake_code = start_def
                if self.funcchain:
                    self.earliest_func = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*local\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name+"0", func_argument)
                else:
                    self.earliest_func = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*local\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name, func_argument)
            
            res = re.search(r'return\s(\w+);', self.fakecodes[func_name])
            pos = 0

            # static and extern are not for vars
            constraints = constraints.replace("static", "").replace("extern", '').replace("local", '')
            while res is not None:
                var_name = res.groups()[0]
                _, offset = res.span()
                pos = pos + offset + len(constraints) + 2
                self.fakecodes[func_name] = self.fakecodes[func_name].replace(ori_func_type+" "+var_name, constraints+" "+ori_func_type+" "+var_name)
                res = re.search(r'return\s(\w+);', self.fakecodes[func_name][pos:])

            
            self.ori_itm_funcs[func_name] = re.sub(r"extern\s*static", "extern ", self.ori_itm_funcs[func_name])
            self.ori_itm_funcs[func_name] = re.sub(r"extern\s*local", "extern ", self.ori_itm_funcs[func_name])
            self.fakecodes[func_name] = re.sub(r"extern\s*static", "extern ", self.fakecodes[func_name])
            self.fakecodes[func_name] = re.sub(r"extern\s*local", "extern ", self.fakecodes[func_name])
            #print(self.fakecodes[func_name])

            if self.funcchain and not self.landingspace:
                self.content = self.content[:start_def] + '\n' + self.fakecodes[func_name] + '\n' + self.content[start_def:]
            
            if self.landingspace:
                self.content = self.content[:start_def] + '\n' + self.fakecodes[func_name] + '\n' + self.content[start_def:func_end+1] + '\n' + self.ori_itm_funcs[func_name] + '\n' + self.content[func_end+1:]


        # Find current main function
        search_pattern = "[^\w]main\s*\(([^;]*?)\)"
        start, end, _ = self.locateFuncBlk(search_pattern, self.content)

        if self.instru_detect:
            fill_funcs_codes += "\ndetect();\n"
        
        if self.daemon_process:
            fill_funcs_codes += '''
FILE *atfz_fp;
char dest_file[30];
sprintf(dest_file, "%s%d", ATFZ_PREFIX, ATFZ_ALERT_NUM);
atfz_fp = fopen(dest_file, "r");
if (atfz_fp){
    printf("Fuzzer detected!\\n");
    abort();
}
creat_daemon();
            '''
        
        self.content = self.content[:start+1] + fill_funcs_codes + self.content[start+1:]

    def constraintIdentify(self):
        pattern = r"(if\s*\(.+(=\s*=|<\s*=|<|[^-]>\s*=|[^-]>|!\s*=).+\s*((\|\|)|(&&).+)*\)[^'])|(switch\s*\(.*\)\s*)"
        pattern2 = r"(if\s*\([^;{]+(=\s*=|<\s*=|<|[^-]>\s*=|[^-]>|!\s*=)[^;{]+?\s*((\|\|)|(&&)[^;{]+)*\))[^']"  
        res = re.findall(pattern, self.content)
        switch_statements = []
        cmp_statements = []
        for cons in res:
            if cons[-1] != '':
                switch_statements.append(cons[-1].strip())
            else:
                cmp_statements.append(cons[0].strip())
        res2 = re.findall(pattern2, self.content, re.DOTALL)
        for cons in res2:
            cmp_statements.append(cons[0].strip().replace("\n", ''))

        # Reduce overheads, one type of statement only be changed in one position
        self.switch_statements = list(set(switch_statements))
        self.cmp_statements = sorted(list(set(cmp_statements)))
        

        #print(self.cmp_statements)

    def gs(self, num):
        if num > 1 or num <= 0:
            return num
        base = 1
        sum = 0
        for i in range(8000):
            sum += base
            base *= num
        return round(sum)

    def cal_loop_num(self, limit):
        if limit < 1:
            raise RuntimeError("Limit should be greater than 1")

        base = 1
        sum = 0
        num = 1-1/limit
        cnt = 0
        while abs(sum-limit) > 0.49:
            sum += base
            base *= num
            cnt += 1
        return cnt


    def constraintTrans(self):
        '''
        gs only deal with variable values in [1, MAXIMUM_OVERLOAD_VALUE]
        constants less than 1000 can always converge in less than 8000 rounds
        '''
        # Dirty hack on double values: /1000000
        gs_template = '''
long gs(long a)
{
    if(a == 0) return a;
    int bit_num = 32;
    if (a > 2147483647 || a < -2147483648) bit_num = 64;
    if (bit_num == 32)
        a = a & 0xffffffff;
    long total_sum = 0, op;
    int rep = 0;
    
    do{
        if ((a>>'''+str(VARMAPPING_BIT)+''')  != 0){
            op = a & ('''+str(1<<VARMAPPING_BIT)+'''-1);
            a >>= '''+str(VARMAPPING_BIT)+''';
        }
        else {
            op = a;
            a = 0;
        }
        double num = (double)1-(double)1/(op);
        double base = 1, sum = 0;
        
        for (int i = 0; i < '''+str(self.cal_loop_num(1<<VARMAPPING_BIT))+'''; i++){
            sum += base;
            base *= num;
            
        }
        
        int tmp = (sum < 0 ? sum - 0.5 : sum + 0.5);
        total_sum += ((long)tmp << (rep*'''+str(VARMAPPING_BIT)+'''));
        rep++;
        
	    if ((rep+1)*'''+str(VARMAPPING_BIT)+''' >= bit_num){
            a = a & ((1<<(bit_num - rep*'''+str(VARMAPPING_BIT)+'''))-1);
            total_sum += ((long)a << (rep*'''+str(VARMAPPING_BIT)+'''));
            break;
        }

    }while (a != 0);
    return total_sum; 
}

'''
        self.def_codes += gs_template

        for switch in self.switch_statements:
            switch_pattern = r"[^\w]{0}[^\w]".format(make_pattern(switch))
            res = re.search(switch_pattern, self.content)
            start, end = res.span()
            offset = self.content[start:end].find("switch")
            start += offset+6
            tmp = self.content[start:end]
            argu = "gs({0})".format(tmp.strip())
            print(tmp)
            self.content = self.content[:start] +"(" +  argu + ")" + self.content[end:]

        
        argu_pattern = r'(.+)(=\s*=|<\s*=|<|[^-]>\s*=|[^-]>|!\s*=)(.+)'
        for if_state in self.cmp_statements:
            tmp = re.split(r"&&|\|\|",if_state[2:].strip()[1:-1])
            if_pattern = make_pattern(if_state)
            cur_pos = 0
            modified = True
            while (True):
                if_res = re.search(if_pattern, self.content[cur_pos:])
                if if_res is None or modified == False:
                    break

                if_start, if_end = if_res.span()
                if_start += cur_pos
                if_end += cur_pos
                
                for cmp in tmp:
                    # Cmp funcs
                                        
                    tcnt = 0
                    break_pos = -1
                    for j in range(len(cmp)):
                        if cmp[j] == '(':
                            tcnt += 1
                        elif cmp[j] == ')':
                            tcnt -= 1
                        if tcnt < 0:
                            break_pos = j+1
                            break
                    if break_pos != -1:
                        cmp = cmp[:break_pos]
                    
                    res = re.search(argu_pattern, cmp)
                    if res is None:
                        modified = False
                        continue

                    
                    lop, operator, rop = res.groups()
                    
                    # Find the left most operator
                    lres = re.search(argu_pattern, lop+" ")
                    
                    while lres is not None:

                        lop, operator, rop = lres.groups()
                        
                        lres = re.match(argu_pattern, lop + " ")
                    
                    pos = cmp.find(operator) + len(operator)
                    rop = cmp[pos:]
                    

                    
                    # Don't deal with nested if statements
                    if check_nested(lop) or check_nested(rop):
                        modified = False
                        continue
                    
                    for symbol in self.noHandleCmpsOperands:
                        if symbol.lower() == lop.strip().lower():
                            lop = ''
                        if symbol.lower() == rop.strip().lower():
                            rop = ''

                    if lop == '' or rop == '':
                        modified = False
                        continue
                    
                   
                    res = re.match(r'(0(x|X)[a-zA-Z\d]+)|(\d+)$', lop.strip())
                    
                    
                    if res is None:
                        if not check_if_constvar(lop.strip()):
                            lop = "gs({0})".format(lop)
                    

                    res = re.search(r'(0(x|X)[a-zA-Z\d]+)|(\d+)|(\'.\')$', rop.strip())
                    
                    if res is None:
                        if not check_if_constvar(rop.strip()):
                            rop = "gs({0})".format(rop)
                    


                    cmp_pattern = make_pattern(cmp)
                    #print(cmp_pattern)
                    t_res = re.search(cmp_pattern, self.content[if_start:if_end])
                    cmp_start, cmp_end = t_res.span()
                    cmp_start += if_start
                    cmp_end += if_start

                    print("replace:", self.content[cmp_start:cmp_end], "   gs:",lop,"##",operator,"##", rop)
                    self.content = self.content[:cmp_start] + lop + operator + rop + self.content[cmp_end:]
                    # recalculate offset
                    if_end += len(lop + operator + rop) - cmp_end + cmp_start
                    cur_pos = if_end


        # change_list = sorted(change_list, key=lambda x:x[0], reverse=True)
        #
        # print(change_list)
        #
        # for i in range(len(change_list)):
        #     start, end, payload = change_list[i]
        #     if end > change_list[i-1][0]:
        #         print(change_list[i], change_list[i-1])
        #     #self.content = self.content[:start] + payload + self.content[end:]

    

    def outputSourcecodes(self):
        '''
        Output the changed source codes and add some initialization codes
        '''

        main_func_pattern = r"\w+\s+main\s*\(.*\)"
        # Dirty hack on ar.c
        for source in self.sources:
            if "ar.c" in source:
                main_func_pattern = r"(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*local\s*|\s*const\s*)*(\w+\s+ranlib_main\s*\(.*\))"
                break

        start_def = 999999999999999
        if self.earliest_func != '':
            _, __, start_def = self.locateFuncBlk(self.earliest_func, self.content)
        
        _, __, main_start_def = self.locateFuncBlk(main_func_pattern, self.content)

        if start_def > main_start_def:
            start_def = main_start_def
        res = re.search(r"#\s*include\s*<\s*std", self.content)
        
        if res is not None:
            include_pos = res.span()[0]
            if include_pos > start_def:
                start_def = include_pos

        if self.funcchain or self.landingspace:
            self.content = self.content[:main_start_def] + "\n" + self.content[main_start_def:]

        if self.instru_detect:
            self.def_codes += self.detect_codes
        
        if self.daemon_process:
            self.def_codes += self.daemon_process_codes


        self.content = self.content[:start_def] + '\n' + self.def_codes + '\n' + self.content[start_def:]
        with open("output.c", "w") as f:
            f.write(self.content)


if __name__ == "__main__":
    print(sys.argv)
    if len(sys.argv) < 2:
        raise RuntimeError("No sufficient parameters")
    if len(sys.argv) > 2:
        CODE_SEG_LEN = int(sys.argv[2])
    if len(sys.argv) > 3:
        TOPN_FREQUENT_FUNCS = int(sys.argv[3])
    if len(sys.argv) > 4:
        LANDING_LEN = int(sys.argv[4])

    anti = Antifuzz([sys.argv[1]], instru_detect=False, daemon_process=True, funcchain=False, landingspace=False)
    anti.funcsIdentify()
    anti.funcTrans()
    
    #anti.constraintIdentify()
    #anti.constraintTrans()
    anti.outputSourcecodes()
    


