import re, random, string, os, sys

CODE_SEG_LEN = 100

TOPN_FREQUENT_FUNCS= 10
INIT_FUNC_NAME = 'ATinit'
COUNTER_NAME = 'ab_count'
FUNC_BUF_NAME = 'funcs_buf'
FUNC_PTR_NAME = 'funcs'
INDEX_NAME = 'funcs_idx'
FUNC_PTR_TYPE_SUFFIX = 'ptr'
INTERMEDIATE_IDENT = 'itm'
MAXIMUM_OVERLOAD_VALUE = 255 # Better no more than 1000

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

    def __init__(self, sources, funcchain = True, constrans = True):
        self.sources = sources
        self.funcchain = funcchain
        self.constrans = constrans
        # self.funcPattern = r"(\w+\s*[\*,&]*)\s+(\w+)\s*\(([^,{})]*),([^,{})]*)\)"

        self.commonFuncs = ['bool', 'int', 'char', 'void', 'float', 'long', 'double', 'wchar_t']
        self.userDefinedTypes = ['bfd_boolean', 'Filedata']
        self.noHandleCmpsOperands = ['NULL', '0', '-1', '1']
        self.funcsList = []
        self.funcCallCnt = {}
        self.toTransFunc = {}
        self.funcPtr = {}
        self.fakecodes = {}
        self.def_codes = '''
#include<stdlib.h>
#include<time.h>
'''


    def genFakeFunc(self, func_type, argu, func_name, func_number):

        
        intermidiate_junk_template = '''
extern {0} {1} ({2});
__asm__ (
"{1}:\n"
"  {2}"
"  jmp {3}\n"
);
'''

        fake_func_ret_template = '''
{0} {1}({2}){{
    {7}
    int {3} = cal_idx('''+COUNTER_NAME+'''++);
    if ({3} != -1){{{0} {4} = (({6})'''+FUNC_PTR_NAME+'''[{3}])({5});
        return {4};
    }}
}}
'''

        fake_func_void_template = ''' 
void {0}({1}){{
    {5}
    int {2} = cal_idx('''+COUNTER_NAME+'''++);
    if ({2} != -1){{(({4})'''+FUNC_PTR_NAME+'''[{2}])({3});
        return;
    }}
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
                return None, None, None
                del self.funcPtr[func_name]
                return None, None, None, None

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
                itm_func = intermidiate_junk_template.format('void', fake_func_name+INTERMEDIATE_IDENT+str(i), argu, fake_func_name + str(i), NOP_NUM*(REPATED_INS+"\\n"))
            
                fake_func = fake_func_void_template.format(fake_func_name + str(i), argu, idx_name, vars, func_name+FUNC_PTR_TYPE_SUFFIX, '')
                fake_key_seg = fake_func.strip('\n').split("\n")
                fake_key_seg = [j for j in fake_key_seg if j.strip() != '']
                fake_key_seg = fake_key_seg[1:3]
            else:
                itm_func = intermidiate_junk_template.format(func_type, fake_func_name+INTERMEDIATE_IDENT+str(i), argu, fake_func_name + str(i), NOP_NUM*(REPATED_INS+"\\n"))
                ret_name = get_random_string(10)
                fake_func = fake_func_ret_template.format(func_type, fake_func_name+str(i), argu, idx_name, ret_name, vars, func_name+FUNC_PTR_TYPE_SUFFIX, '')
                fake_key_seg = fake_func.strip('\n').strip().split("\n")
                fake_key_seg = [j for j in fake_key_seg if j.strip() != '']
                fake_key_seg = fake_key_seg[1:3]
            
            code_seg += fake_func
            code_seg += itm_func
            

        if func_type.lower() == 'void':
            init_func = fake_func_void_template.format(fake_func_name+INIT_FUNC_NAME, argu, idx_name, vars, func_name + FUNC_PTR_TYPE_SUFFIX, COUNTER_NAME + ' = 0;\n'+FUNC_PTR_NAME+' = %s;')
        else:
            ret_name = get_random_string(10)
            init_func = fake_func_ret_template.format(func_type, fake_func_name+INIT_FUNC_NAME, argu, idx_name, ret_name, vars, func_name + FUNC_PTR_TYPE_SUFFIX, COUNTER_NAME + ' = 0;\n'+FUNC_PTR_NAME+' = %s;')

        origin_itm_func = intermidiate_junk_template.format(func_type, fake_func_name+INTERMEDIATE_IDENT, argu, fake_func_name, NOP_NUM*(REPATED_INS+"\\n"))

        return code_seg, fake_key_seg, init_func, origin_itm_func


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
            if tmp in self.commonFuncs or tmp in self.userDefinedTypes:
                #print(func)
                self.funcsList.append(func)

        for func in self.funcsList:
            func_type = func[0]
            func_name = func[1]
            func_argument = func[2]

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

        insert_codes_ident = '#############For anti fuzz###############'
        main_codes_rand_init = main_codes[0] + insert_codes_ident + main_codes[1:]

        if self.funcchain:
        # Random initialization
            self.content = self.content.replace(main_codes, main_codes_rand_init.replace(insert_codes_ident, 'time_t timestamp;\nsrand((unsigned) time(&timestamp));\n'))

        # print(self.toTransFunc)


    def funcTrans(self):
        '''
        int cal_idx(int count)
        {
            if (!count)
                for (int i = 0; i < 1000; index[i++]=i-1);
            int idx = rand() % (1000-count);
            for (int i = idx; i < 1000-count-1; i++)index[i] = index[i+1];
            return idx;
        }

        int ab_count = 0;
        int index[CODE_SEG_LEN] = {};
        void** funcs;

        // Replace function call with

        ab_count = 0;
        int idx = cal_idx(ab_count++);

        ret = ((fp)funcs[idx])(argu);
        return ret
        '''

        if len(self.toTransFunc) == 0:
            print("No functions identified")
            return

        # Find function definitions, add fake path to definitions, and create their fake copies

        init_funcs = {}
        for func_name, func_info in self.toTransFunc.items():
            print("#####", func_name)
            func_type = func_info[0]
            ori_func_argument = func_info[1]
            # Remove some control symbols for a better view
            func_argument = ori_func_argument.strip().replace("\t", '').replace("\n", '').replace("  ", " ")
            added_code_seg, ins_code_seg, init_func, origin_itm_func = self.genFakeFunc(func_type, func_argument, func_name, CODE_SEG_LEN-1)
            if added_code_seg is None:
                continue 

            self.fakecodes[func_name] = ''
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

            if self.funcchain:
                self.content = self.content[:start]+func_code+self.content[end+1:]

            self.fakecodes[func_name] += added_code_seg

        cal_idx = '''
static void **''' + FUNC_PTR_NAME + ''';
static int ''' + COUNTER_NAME + ''' = 0;
static int ''' + INDEX_NAME + '''[{0}] = {{}};
static void (*''' + FUNC_BUF_NAME + '''[''' + str(CODE_SEG_LEN * len(self.funcPtr)) + ''']) = {{}};
int cal_idx(int count)
{{
    if (!count)
        for (int i = 0; i < {0}; ''' + INDEX_NAME + '''[i++]=i-1);
    int remaining = {0} - count;
    if(remaining <= 0) return -1;
    int idx = rand() % (remaining);
    int res = ''' + INDEX_NAME + '''[idx];
    ''' + INDEX_NAME + '''[idx] = ''' + INDEX_NAME + '''[remaining-1];
    return res;
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
            tmp_list = [func_name+INTERMEDIATE_IDENT+str(id) for id in range(CODE_SEG_LEN-1)]
            tmp_list = tmp_list[:real_func_pos] + [func_name+INTERMEDIATE_IDENT] + tmp_list[real_func_pos:]
            funcs_list += tmp_list
            funcs_pos[func_name] = cnt
            cnt += 1

        # Function list fill addresses of functions
        fill_funcs_codes = ''
        func_assignment = FUNC_BUF_NAME+'[{0}] = {1};'
        for i in range(len(funcs_list)):
            fill_funcs_codes += func_assignment.format(i, funcs_list[i])

        # Function calls initialization
        for func_name,l in self.funcPtr.items():
            tmp = init_funcs[func_name].replace("rand()%", "rand()%%")
            self.fakecodes[func_name] += tmp%('&'+FUNC_BUF_NAME+'[{0}]'.format(funcs_pos[func_name]*CODE_SEG_LEN))

        if self.funcchain:
        # Replace function calls with init functions
            for func_name in self.funcPtr.keys():
                func_argument = self.toTransFunc[func_name][1]
                res = re.search(pattern, self.content[search_start:])
                while res is not None:
                    found_call = res.group()
                    call_start, new_start = res.span()
                    call_start += search_start
                    new_start += search_start
                    if func_name == 'print_archive_filename_bsd':
                        print(func_argument)
                    if "," in func_argument:
                        func_argument = func_argument.split(",")[0]
                    if re.search(make_pattern(func_argument), found_call) is not None:
                        search_start = new_start
                    else:
                        self.content[call_start:new_start].replace(func_name, func_name+IN:QQQTERSIIII +INIT_FUNC_NAME, 1) + \
                                       self.content[new_start:]

                    res = re.search(pattern, self.content[search_start:])

        earliest_fake_code = 99999999999999999
        self.earliest_func = ''
        # Add fake function copies and initialization
        for func_name in self.funcPtr.keys():

            ori_func_type = self.toTransFunc[func_name][0]
            func_argument = self.toTransFunc[func_name][1]
            func_type = make_pattern(ori_func_type)
            func_argument = make_pattern(func_argument)

            with open("tmp.c", "w") as f:
                f.write(self.content)
            # Match '{' avoid matching a declaration
            search_pattern = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name, func_argument)
            _, __, start_def = self.locateFuncBlk(search_pattern, self.content)

            function_def = self.content[start_def:_]
            res = re.search(func_type, function_def)
            func_pos, _ = res.span()
            constraints = function_def[:func_pos].strip()
            # Add constraints
            self.fakecodes[func_name] = self.fakecodes[func_name].replace(ori_func_type+" "+func_name, constraints+" "+ori_func_type+" "+func_name)

            if earliest_fake_code > start_def:
                earliest_fake_code = start_def
                if self.funcchain:
                    self.earliest_func = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name+"0", func_argument)
                else:
                    self.earliest_func = "(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*\s*{0}\s*{1}\s*\(\s*{2}\s*\)\s*{{".format(func_type, func_name, func_argument)

            res = re.search(r'return\s(\w+);', self.fakecodes[func_name])
            pos = 0

            # static and extern are not for vars
            constraints = constraints.replace("static", "").replace("extern", '')
            while res is not None:
                var_name = res.groups()[0]
                _, offset = res.span()
                pos = pos + offset + len(constraints) + 2
                self.fakecodes[func_name] = self.fakecodes[func_name].replace(ori_func_type+" "+var_name, constraints+" "+ori_func_type+" "+var_name)
                res = re.search(r'return\s(\w+);', self.fakecodes[func_name][pos:])

            if self.funcchain:
                self.content = self.content[:start_def] + '\n' + self.fakecodes[func_name] + '\n' + self.content[start_def:]

        # Find current main function
        search_pattern = "[^\w]main\s*\(([^;]*?)\)"
        start, end, _ = self.locateFuncBlk(search_pattern, self.content)
        if self.funcchain:


        # Find current main function
        search_pattern = "[^\w]main\s*\(([^;]*?)\)"
        start, end, _ = self.locateFuncBlk(search_pattern, self.content)
        if self.funcchain:
            self.content = self.content[:start+1] + fill_funcs_codes + self.content[start+1:]


        # print(self.funcsList)


    def constraintIdentify(self):
        pattern = r"(if\s*\(.+(<\s*=|<|[^-]>\s*=|[^-]>|=\s*=|!\s*=).+\s*((\|\|)|(&&).+)*\))|(switch\s*\(.*\)\s*)"
        res = re.findall(pattern, self.content)
        switch_statements = []
        cmp_statements = []
        for cons in res:
            if cons[-1] != '':
                switch_statements.append(cons[-1].strip())
            else:
                cmp_statements.append(cons[0].strip())

        # Reduce overheads, one type of statement only be changed in one position
        self.switch_statements = list(set(switch_statements))
        self.cmp_statements = list(set(cmp_statements))


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
long gs(long a, int is_var)
{
    if (is_var && (a > '''+str(MAXIMUM_OVERLOAD_VALUE)+''' || a <= 1)) return a;
    double base = 1.0, sum = 0.0;
    double num;
    if (is_var) num = (double)1 - (double)1/a;
    else num = (double)a/1000000;    
    for (int i = 0; i < '''+str(self.cal_loop_num(MAXIMUM_OVERLOAD_VALUE))+'''; i++){
        sum += base;
        base *= num;
    }
    return sum < 0 ? sum - 0.5 : sum + 0.5; 
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
            argu = "gs({0},1)".format(tmp.strip())

            self.content = self.content[:start] +"(" +  argu + ")" + self.content[end:]

        cnt = 0
        argu_pattern = r'(.+)(<\s*=|<|[^-]>\s*=|[^-]>|=\s*=|!\s*=)(.+)'
        for if_state in self.cmp_statements:
            tmp = re.split(r"&&|\|\|",if_state[2:].strip()[1:-1])

            if_pattern = make_pattern(if_state)
            if_res = re.search(if_pattern, self.content)

            if if_res is None:
                continue
            if_start, if_end = if_res.span()
            cnt += 1
            for cmp in tmp:
                # Cmp funcs

                res = re.match(argu_pattern, cmp)
                if res is None:
                    continue
                lop, operator, rop = res.groups()

                # Don't deal with nested if statements
                if check_nested(lop) or check_nested(rop):
                    continue

                for symbol in self.noHandleCmpsOperands:
                    if symbol.lower() == lop.strip().lower():
                        lop = ''
                    if symbol.lower() == rop.strip().lower():
                        rop = ''
                if lop == '' or rop == '':
                    continue

                #print(lop, operator, rop)

                res = re.match(r'(0(x|X)[a-zA-Z\d]+)|(\d+)$', lop.strip())

                if res is None:
                    if not check_if_constvar(lop.strip()):
                        lop = "gs({0}, 1)".format(lop)
                else:
                    # Constant
                    value = res.group()
                    if "0x" in value or "0X" in value:
                        value = int(value, 16)
                    else:
                        value = int(value)

                    ori_value = value
                    if value <= MAXIMUM_OVERLOAD_VALUE and value > 1:
                        # Dirty hack to avoid directly pass arguments of type double
                        value = round(1 - 1 / value, 6) * 1000000
                        assert ori_value == self.gs(value/1000000), "gs not equal!"
                        lop = "gs({0}, 0)".format(int(value))


                res = re.match(r'(0(x|X)[a-zA-Z\d]+)|(\d+)|(\'[\w ]\')$', rop.strip())
                if res is None:
                    if not check_if_constvar(rop.strip()):
                        rop = "gs({0}, 1)".format(rop)
                else:
                    value = res.group()
                    if "0x" in value or "0X" in value:
                        value = int(value, 16)
                    elif "'" in value:
                        value = ord(value[1])
                    else:
                        value = int(value)

                    ori_value = value
                    if value <= MAXIMUM_OVERLOAD_VALUE and value > 1:
                        value = round(1 - 1 / value, 6) * 1000000
                        assert ori_value == self.gs(value/1000000), "gs not equal!"
                        rop = "gs({0}, 0)".format(int(value))


                cmp_pattern = make_pattern(cmp)

                t_res = re.search(cmp_pattern, self.content[if_start:if_end])
                cmp_start, cmp_end = t_res.span()
                cmp_start += if_start
                cmp_end += if_start

                self.content = self.content[:cmp_start] + lop + operator + rop + self.content[cmp_end:]
                # recalculate offset
                if_end += len(lop + operator + rop) - cmp_end + cmp_start


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
                main_func_pattern = r"(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*(\w+\s+ranlib_main\s*\(.*\))"
                break
        _, __, start_def = self.locateFuncBlk(self.earliest_func, self.content)
        _, __, main_start_def = self.locateFuncBlk(main_func_pattern, self.content)

        if start_def > main_start_def:
            start_def = main_start_def
        res = re.search(r"#\s*include\s*<\s*std", self.content)

        for funcname in self.fakecodes.keys():


            def_pattern = r'(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*(\w+ \w+\(.*\){)'
            res = re.findall(def_pattern, self.fakecodes[funcname])

            for func_def in res:
                if type(func_def) is tuple:
                    func_def = ' '.join(func_def)
                    func_def.replace("\n", '')
                main_def_codes += func_def[:-1]+";\n"

            def_pattern = r'(\s*extern\s*|\s*unsigned\s*|\s*inline\s*|\s*signed\s*|\s*static\s*|\s*const\s*)*(\w+\s*(\s+|\*+)\s*%s\s*\([^;]*?\))'%(funcname)
            res = re.search(def_pattern, self.content)
            main_def_codes += res.group().strip() + ";\n"

        # Find the position of first non include or define statement
        self.content = self.content[:main_start_def] + "\n" + main_def_codes + self.content[main_start_def:]
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

    anti = Antifuzz([sys.argv[1]], funcchain=True)
    anti.funcsIdentify()
    anti.funcTrans()

    #anti.constraintIdentify()
    #anti.constraintTrans()
    anti.outputSourcecodes()
    #anti.GS_test(1000)

