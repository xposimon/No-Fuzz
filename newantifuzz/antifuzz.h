
#ifndef _ANTIFUZZ_H_
#define _ANTIFUZZ_H_
#include<stdlib.h>
#include<time.h>
void **funcs;
int ab_count = 0;
int funcs_idx[2] = {};

int cal_idx(int count)
{
    if (!count)
        for (int i = 0; i < 2; funcs_idx[i++]=i-1);
    int remaining = 2 - count;
    if(remaining <= 0) return -1;
    int idx = rand() % (remaining);
    int res = funcs_idx[idx];
    for (int i = idx; i < 2-count-1; i++)funcs_idx[i] = funcs_idx[i+1];
    return res;
}
        
typedef int (*print_vmaptr) (bfd_vma,print_mode);
typedef void * (*get_dataptr) (void *,Filedata *,unsigned long,bfd_size_type,bfd_size_type,char *);
typedef char * (*printable_section_nameptr) (Filedata *,Elf_Internal_Shdr *);
typedef long (*offset_from_vmaptr) (Filedata *,bfd_vma,bfd_size_type);
typedef char * (*display_tag_valueptr) (signed int,unsigned char *,unsigned char *);
typedef char * (*bfd_vmatoaptr) (char *,bfd_vma);
typedef bfd_boolean (*is_ia64_vmsptr) (Filedata *);
typedef bfd_boolean (*slurp_rela_relocsptr) (Filedata *,unsigned long,unsigned long,Elf_Internal_Rela **,unsigned long *);
typedef int (*get_reloc_typeptr) (Filedata *,bfd_vma);
typedef void (*usageptr) (FILE *);
typedef void (*parse_argsptr) (Filedata *,int,char **);
typedef bfd_boolean (*process_fileptr) (char *);

int print_vma0(bfd_vma vma, print_mode mode){
    
    int KHLXt = cal_idx(ab_count++);
    if (KHLXt != -1){int wvSicTbE = ((print_vmaptr)funcs[KHLXt])(vma,mode);
        return wvSicTbE;
    }
}
        
int print_vma(bfd_vma vma, print_mode mode);
        
void * get_data0(void *     var, Filedata *   filedata, unsigned long offset, bfd_size_type size, bfd_size_type nmemb, const char *  reason){
    
    int VhLgb = cal_idx(ab_count++);
    if (VhLgb != -1){void * PAVHadXz = ((get_dataptr)funcs[VhLgb])(var,filedata,offset,size,nmemb,reason);
        return PAVHadXz;
    }
}
        
void * get_data(void *     var, Filedata *   filedata, unsigned long offset, bfd_size_type size, bfd_size_type nmemb, const char *  reason);
        
char * printable_section_name0(Filedata * filedata, const Elf_Internal_Shdr * sec){
    
    int YSSsl = cal_idx(ab_count++);
    if (YSSsl != -1){char * eHPVqUTh = ((printable_section_nameptr)funcs[YSSsl])(filedata,sec);
        return eHPVqUTh;
    }
}
        
char * printable_section_name(Filedata * filedata, const Elf_Internal_Shdr * sec);
        
long offset_from_vma0(Filedata * filedata, bfd_vma vma, bfd_size_type size){
    
    int XVGDD = cal_idx(ab_count++);
    if (XVGDD != -1){long sAkX = ((offset_from_vmaptr)funcs[XVGDD])(filedata,vma,size);
        return sAkX;
    }
}
        
long offset_from_vma(Filedata * filedata, bfd_vma vma, bfd_size_type size);
        
char * display_tag_value0(signed int tag,  unsigned char * p,  const unsigned char * const end){
    
    int LHJe = cal_idx(ab_count++);
    if (LHJe != -1){char * wccAVvwt = ((display_tag_valueptr)funcs[LHJe])(tag,p,end);
        return wccAVvwt;
    }
}
        
char * display_tag_value(signed int tag,  unsigned char * p,  const unsigned char * const end);
        
char * bfd_vmatoa0(char *fmtch, bfd_vma value){
    
    int EQGu = cal_idx(ab_count++);
    if (EQGu != -1){char * ShSiE = ((bfd_vmatoaptr)funcs[EQGu])(fmtch,value);
        return ShSiE;
    }
}
        
char * bfd_vmatoa(char *fmtch, bfd_vma value);
        
bfd_boolean is_ia64_vms0(Filedata * filedata){
    
    int DiFk = cal_idx(ab_count++);
    if (DiFk != -1){bfd_boolean tYquXiscwo = ((is_ia64_vmsptr)funcs[DiFk])(filedata);
        return tYquXiscwo;
    }
}
        
bfd_boolean is_ia64_vms(Filedata * filedata);
        
bfd_boolean slurp_rela_relocs0(Filedata *      filedata,  unsigned long     rel_offset,  unsigned long     rel_size,  Elf_Internal_Rela ** relasp,  unsigned long *    nrelasp){
    
    int Crpgc = cal_idx(ab_count++);
    if (Crpgc != -1){bfd_boolean qysgxttRYX = ((slurp_rela_relocsptr)funcs[Crpgc])(filedata,rel_offset,rel_size,relasp,nrelasp);
        return qysgxttRYX;
    }
}
        
bfd_boolean slurp_rela_relocs(Filedata *      filedata,  unsigned long     rel_offset,  unsigned long     rel_size,  Elf_Internal_Rela ** relasp,  unsigned long *    nrelasp);
        
int get_reloc_type0(Filedata * filedata, bfd_vma reloc_info){
    
    int ucGa = cal_idx(ab_count++);
    if (ucGa != -1){int YRuUvKJ = ((get_reloc_typeptr)funcs[ucGa])(filedata,reloc_info);
        return YRuUvKJ;
    }
}
        
int get_reloc_type(Filedata * filedata, bfd_vma reloc_info);
         
void usage0(FILE * stream){
    
    int oFtC = cal_idx(ab_count++);
    if (oFtC != -1){((usageptr)funcs[oFtC])(stream);
        return;
    }
}
        
void usage(FILE * stream);
         
void parse_args0(Filedata * filedata, int argc, char ** argv){
    
    int gFmVW = cal_idx(ab_count++);
    if (gFmVW != -1){((parse_argsptr)funcs[gFmVW])(filedata,argc,argv);
        return;
    }
}
        
void parse_args(Filedata * filedata, int argc, char ** argv);
        
bfd_boolean process_file0(char * file_name){
    
    int ySeE = cal_idx(ab_count++);
    if (ySeE != -1){bfd_boolean sytVNPYQi = ((process_fileptr)funcs[ySeE])(file_name);
        return sytVNPYQi;
    }
}
        
bfd_boolean process_file(char * file_name);
        
void (*funcs_buf[]) = {print_vma,print_vma0,get_data,get_data0,printable_section_name0,printable_section_name,offset_from_vma,offset_from_vma0,display_tag_value,display_tag_value0,bfd_vmatoa0,bfd_vmatoa,is_ia64_vms0,is_ia64_vms,slurp_rela_relocs,slurp_rela_relocs0,get_reloc_type0,get_reloc_type,usage0,usage,parse_args0,parse_args,process_file0,process_file};
        
int print_vmaATinit(bfd_vma vma, print_mode mode){
    ab_count = 0;
funcs = &funcs_buf[0];
    int KHLXt = cal_idx(ab_count++);
    if (KHLXt != -1){int ApMdtaa = ((print_vmaptr)funcs[KHLXt])(vma,mode);
        return ApMdtaa;
    }
}
        
void * get_dataATinit(void *     var, Filedata *   filedata, unsigned long offset, bfd_size_type size, bfd_size_type nmemb, const char *  reason){
    ab_count = 0;
funcs = &funcs_buf[2];
    int VhLgb = cal_idx(ab_count++);
    if (VhLgb != -1){void * kKPGCX = ((get_dataptr)funcs[VhLgb])(var,filedata,offset,size,nmemb,reason);
        return kKPGCX;
    }
}
        
char * printable_section_nameATinit(Filedata * filedata, const Elf_Internal_Shdr * sec){
    ab_count = 0;
funcs = &funcs_buf[4];
    int YSSsl = cal_idx(ab_count++);
    if (YSSsl != -1){char * MqPHAcGW = ((printable_section_nameptr)funcs[YSSsl])(filedata,sec);
        return MqPHAcGW;
    }
}
        
long offset_from_vmaATinit(Filedata * filedata, bfd_vma vma, bfd_size_type size){
    ab_count = 0;
funcs = &funcs_buf[6];
    int XVGDD = cal_idx(ab_count++);
    if (XVGDD != -1){long pwtVAbzcZZ = ((offset_from_vmaptr)funcs[XVGDD])(filedata,vma,size);
        return pwtVAbzcZZ;
    }
}
        
char * display_tag_valueATinit(signed int tag,  unsigned char * p,  const unsigned char * const end){
    ab_count = 0;
funcs = &funcs_buf[8];
    int LHJe = cal_idx(ab_count++);
    if (LHJe != -1){char * mdKH = ((display_tag_valueptr)funcs[LHJe])(tag,p,end);
        return mdKH;
    }
}
        
char * bfd_vmatoaATinit(char *fmtch, bfd_vma value){
    ab_count = 0;
funcs = &funcs_buf[10];
    int EQGu = cal_idx(ab_count++);
    if (EQGu != -1){char * yVsHDAY = ((bfd_vmatoaptr)funcs[EQGu])(fmtch,value);
        return yVsHDAY;
    }
}
        
bfd_boolean is_ia64_vmsATinit(Filedata * filedata){
    ab_count = 0;
funcs = &funcs_buf[12];
    int DiFk = cal_idx(ab_count++);
    if (DiFk != -1){bfd_boolean ZcgbqT = ((is_ia64_vmsptr)funcs[DiFk])(filedata);
        return ZcgbqT;
    }
}
        
bfd_boolean slurp_rela_relocsATinit(Filedata *      filedata,  unsigned long     rel_offset,  unsigned long     rel_size,  Elf_Internal_Rela ** relasp,  unsigned long *    nrelasp){
    ab_count = 0;
funcs = &funcs_buf[14];
    int Crpgc = cal_idx(ab_count++);
    if (Crpgc != -1){bfd_boolean ROZmrmrLf = ((slurp_rela_relocsptr)funcs[Crpgc])(filedata,rel_offset,rel_size,relasp,nrelasp);
        return ROZmrmrLf;
    }
}
        
int get_reloc_typeATinit(Filedata * filedata, bfd_vma reloc_info){
    ab_count = 0;
funcs = &funcs_buf[16];
    int ucGa = cal_idx(ab_count++);
    if (ucGa != -1){int PzVRE = ((get_reloc_typeptr)funcs[ucGa])(filedata,reloc_info);
        return PzVRE;
    }
}
         
void usageATinit(FILE * stream){
    ab_count = 0;
funcs = &funcs_buf[18];
    int oFtC = cal_idx(ab_count++);
    if (oFtC != -1){((usageptr)funcs[oFtC])(stream);
        return;
    }
}
         
void parse_argsATinit(Filedata * filedata, int argc, char ** argv){
    ab_count = 0;
funcs = &funcs_buf[20];
    int gFmVW = cal_idx(ab_count++);
    if (gFmVW != -1){((parse_argsptr)funcs[gFmVW])(filedata,argc,argv);
        return;
    }
}
        
bfd_boolean process_fileATinit(char * file_name){
    ab_count = 0;
funcs = &funcs_buf[22];
    int ySeE = cal_idx(ab_count++);
    if (ySeE != -1){bfd_boolean WFrOoFUnn = ((process_fileptr)funcs[ySeE])(file_name);
        return WFrOoFUnn;
    }
}
        