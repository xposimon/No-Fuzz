#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
using std::cerr;
using std::string;
using std::endl;

std::ostream * out = &cerr;
UINT64 curTime = 0;

class EXEC_TIME
{
public:
    UINT64 exec_sum_time;
    UINT32 blk_hit;
    ADDRINT pre_blk_addr;

    EXEC_TIME()
    {
        exec_sum_time = 0;
        blk_hit = 0;
        pre_blk_addr = 0;
    }

    UINT32 get_avg_time(){
        return (UINT32)(exec_sum_time / (UINT64)blk_hit);
    }
};

std::map<ADDRINT, EXEC_TIME> exec_times;
ADDRINT pre_blk_addr = 0;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<string> KnobPathStartBlk(KNOB_MODE_WRITEONCE,  "pintool",
    "j", "", "[start_addr]->[jmp_addr]");

KNOB<string> KnobPathStartBlk(KNOB_MODE_WRITEONCE,  "pintool",
    "S", "", "store the status of [input] blk");

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

VOID BBLTimeRecord(UINT64 timestamp, ADDRINT blk_addr)
{
    UINT64 tmp;

    if (curTime == 0)
    {
        curTime = timestamp;
        pre_blk_addr = blk_addr;
        return;
    }
    else {
        tmp = timestamp - curTime;
        curTime = timestamp;
    }
    if (exec_times.find(blk_addr) == exec_times.end())
    {
        exec_times[blk_addr] = EXEC_TIME();
    }
    exec_times[blk_addr].exec_sum_time += tmp;
    exec_times[blk_addr].blk_hit ++;
    if (exec_times[blk_addr].pre_blk_addr == 0)
        exec_times[blk_addr].pre_blk_addr = pre_blk_addr;
    pre_blk_addr = blk_addr;
}

VOID PathTrace(TRACE trace, VOID *v)
{
    // Record execution time of every blk visited
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBLTimeRecord,
                                            IARG_TSC,
                                            IARG_ADDRINT, BBL_Address(bbl),
                                            IARG_END);
    }
}

VOID JmpTrace(TRACE trace, void *v)
{

    
}

VOID PathTraceFini(INT32 code, VOID *v)
{
    for(auto &v : exec_times)
    {
        *out << v.first <<" : "<<v.second.exec_sum_time / v.second.blk_hit << \
        " * " << v.second.blk_hit << " <- " << v.second.pre_blk_addr << std::endl;

    }
}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();

    if (fileName.empty()){ fileName = string("result.out");}
    out = new std::ofstream(fileName.c_str());}

    cerr << "Output filename:" << fileName << endl;


    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(PathTrace, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(PathTraceFini, 0);

    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */