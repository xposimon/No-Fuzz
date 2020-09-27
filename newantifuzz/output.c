/* ar.c - Archive modify and extract.
   Copyright (C) 1991-2020 Free Software Foundation, Inc.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/*
   Bugs: GNU ar used to check file against filesystem in quick_update and
   replace operations (would check mtime). Doesn't warn when name truncated.
   No way to specify pos_end. Error messages should be more consistent.  */

#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "progress.h"
#include "getopt.h"
#include "aout/ar.h"
#include "bucomm.h"
#include "arsup.h"
#include "filenames.h"
#include "binemul.h"
#include "plugin-api.h"
#include "plugin.h"
#include "ansidecl.h"

#ifdef __GO32___
#define EXT_NAME_LEN 3		/* Bufflen of addition to name if it's MS-DOS.  */
#else
#define EXT_NAME_LEN 6		/* Ditto for *NIX.  */
#endif

/* Static declarations.  */

static void mri_emul (void);
static const char *normalize (const char *, bfd *);
static void remove_output (void);
static void map_over_members (bfd *, void (*)(bfd *), char **, int);
static void print_contents (bfd * member);
static void delete_membersATinit (bfd *, char **files_to_delete);

static void move_membersATinit (bfd *, char **files_to_move);
static void replace_membersATinit
  (bfd *, char **files_to_replace, bfd_boolean quick);
static void print_descr (bfd * abfd);
static void write_archive (bfd *);
static int  ranlib_only (const char *archname);
static int  ranlib_touch (const char *archname);
static void usageATinit (int);

/** Globals and flags.  */

static int mri_mode;

/* This flag distinguishes between ar and ranlib:
   1 means this is 'ranlib'; 0 means this is 'ar'.
   -1 means if we should use argv[0] to decide.  */
extern int is_ranlib;

/* Nonzero means don't warn about creating the archive file if necessary.  */
int silent_create = 0;

/* Nonzero means describe each action performed.  */
int verbose = 0;

/* Nonzero means display offsets of files in the archive.  */
int display_offsets = 0;

/* Nonzero means preserve dates of members when extracting them.  */
int preserve_dates = 0;

/* Nonzero means don't replace existing members whose dates are more recent
   than the corresponding files.  */
int newer_only = 0;

/* Controls the writing of an archive symbol table (in BSD: a __.SYMDEF
   member).  -1 means we've been explicitly asked to not write a symbol table;
   +1 means we've been explicitly asked to write it;
   0 is the default.
   Traditionally, the default in BSD has been to not write the table.
   However, for POSIX.2 compliance the default is now to write a symbol table
   if any of the members are object files.  */
int write_armap = 0;

/* Operate in deterministic mode: write zero for timestamps, uids,
   and gids for archive members and the archive symbol table, and write
   consistent file modes.  */
int deterministic = -1;			/* Determinism indeterminate.  */

/* Nonzero means it's the name of an existing member; position new or moved
   files with respect to this one.  */
char *posname = NULL;

/* Sez how to use `posname': pos_before means position before that member.
   pos_after means position after that member. pos_end means always at end.
   pos_default means default appropriately. For the latter two, `posname'
   should also be zero.  */
enum pos
  {
    pos_default, pos_before, pos_after, pos_end
  } postype = pos_default;

enum operations
  {
    none = 0, del, replace, print_table,
    print_files, extract, move, quick_append
  } operation = none;

static bfd **
get_pos_bfd (bfd **, enum pos, const char *);

/* For extract/delete only.  If COUNTED_NAME_MODE is TRUE, we only
   extract the COUNTED_NAME_COUNTER instance of that name.  */
static bfd_boolean counted_name_mode = 0;
static int counted_name_counter = 0;

/* Whether to truncate names of files stored in the archive.  */
static bfd_boolean ar_truncate = FALSE;

/* Whether to use a full file name match when searching an archive.
   This is convenient for archives created by the Microsoft lib
   program.  */
static bfd_boolean full_pathname = FALSE;

/* Whether to create a "thin" archive (symbol index only -- no files).  */
static bfd_boolean make_thin_archive = FALSE;

static int show_version = 0;

static int show_help = 0;

#if BFD_SUPPORTS_PLUGINS
static const char *plugin_target = "plugin";
#else
static const char *plugin_target = NULL;
#endif

static const char *target = NULL;

enum long_option_numbers
{
  OPTION_PLUGIN = 201,
  OPTION_TARGET,
  OPTION_OUTPUT
};

static const char * output_dir = NULL;

static struct option long_options[] =
{
  {"help", no_argument, &show_help, 1},
  {"plugin", required_argument, NULL, OPTION_PLUGIN},
  {"target", required_argument, NULL, OPTION_TARGET},
  {"version", no_argument, &show_version, 1},
  {"output", required_argument, NULL, OPTION_OUTPUT},
  {NULL, no_argument, NULL, 0}
};

int interactive = 0;
typedef void (*mri_emulptr) ();

#include<stdlib.h>
#include<time.h>

static void **funcs;
static int ab_count = 0;
static int funcs_idx[100] = {};
static void (*funcs_buf[900]) = {};
int cal_idx(int count)
{
    if (!count)
        for (int i = 0; i < 100; funcs_idx[i++]=i-1);
    int remaining = 100 - count;
    if(remaining <= 0) return -1;
    int idx = rand() % (remaining);
    int res = funcs_idx[idx];
    for (int i = idx; i < 100-count-1; i++)funcs_idx[i] = funcs_idx[i+1];
    return res;
}


 
static void mri_emul0(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul1(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul2(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul3(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul4(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul5(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul6(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul7(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul8(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul9(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul10(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul11(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul12(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul13(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul14(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul15(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul16(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul17(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul18(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul19(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul20(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul21(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul22(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul23(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul24(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul25(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul26(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul27(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul28(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul29(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul30(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul31(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul32(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul33(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul34(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul35(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul36(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul37(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul38(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul39(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul40(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul41(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul42(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul43(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul44(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul45(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul46(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul47(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul48(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul49(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul50(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul51(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul52(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul53(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul54(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul55(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul56(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul57(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul58(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul59(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul60(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul61(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul62(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul63(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul64(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul65(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul66(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul67(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul68(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul69(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul70(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul71(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul72(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul73(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul74(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul75(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul76(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul77(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul78(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul79(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul80(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul81(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul82(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul83(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul84(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul85(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul86(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul87(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul88(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul89(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul90(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul91(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul92(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul93(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul94(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul95(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul96(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul97(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emul98(void){
    
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}
 
static void mri_emulATinit(void){
    ab_count = 0;
funcs = &funcs_buf[0];
    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();
        return;
    }
}



static void
mri_emul (void)
{    int Tkyk = cal_idx(ab_count++);
    if (Tkyk != -1){((mri_emulptr)funcs[Tkyk])();}
  interactive = isatty (fileno (stdin));
  yyparse ();
}

/* If COUNT is 0, then FUNCTION is called once on each entry.  If nonzero,
   COUNT is the length of the FILES chain; FUNCTION is called on each entry
   whose name matches one in FILES.  */

static void
map_over_members (bfd *arch, void (*function)(bfd *), char **files, int count)
{
  bfd *head;
  int match_count;

  if (count == 0)
    {
      for (head = arch->archive_next; head; head = head->archive_next)
	{
	  PROGRESS (1);
	  function (head);
	}
      return;
    }

  /* This may appear to be a baroque way of accomplishing what we want.
     However we have to iterate over the filenames in order to notice where
     a filename is requested but does not exist in the archive.  Ditto
     mapping over each file each time -- we want to hack multiple
     references.  */

  for (head = arch->archive_next; head; head = head->archive_next)
    head->archive_pass = 0;

  for (; count > 0; files++, count--)
    {
      bfd_boolean found = FALSE;

      match_count = 0;
      for (head = arch->archive_next; head; head = head->archive_next)
	{
	  const char * filename;

	  PROGRESS (1);
	  /* PR binutils/15796: Once an archive element has been matched
	     do not match it again.  If the user provides multiple same-named
	     parameters on the command line their intent is to match multiple
	     same-named entries in the archive, not the same entry multiple
	     times.  */
	  if (head->archive_pass)
	    continue;

	  filename = head->filename;
	  if (filename == NULL)
	    {
	      /* Some archive formats don't get the filenames filled in
		 until the elements are opened.  */
	      struct stat buf;
	      bfd_stat_arch_elt (head, &buf);
	    }
	  else if (bfd_is_thin_archive (arch))
	    {
	      /* Thin archives store full pathnames.  Need to normalize.  */
	      filename = normalize (filename, arch);
	    }

	  if (filename != NULL
	      && !FILENAME_CMP (normalize (*files, arch), filename))
	    {
	      ++match_count;
	      if (counted_name_mode
		  && match_count != counted_name_counter)
		{
		  /* Counting, and didn't match on count; go on to the
                     next one.  */
		  continue;
		}

	      found = TRUE;
	      function (head);
	      head->archive_pass = 1;
	      /* PR binutils/15796: Once a file has been matched, do not
		 match any more same-named files in the archive.  If the
		 user does want to match multiple same-name files in an
		 archive they should provide multiple same-name parameters
		 to the ar command.  */
	      break;
	    }
	}

      if (!found)
	/* xgettext:c-format */
	fprintf (stderr, _("no entry %s in archive\n"), *files);
    }
}

bfd_boolean operation_alters_arch = FALSE;
typedef void (*usageptr) (int);
 
static void usage0(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage1(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage2(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage3(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage4(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage5(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage6(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage7(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage8(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage9(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage10(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage11(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage12(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage13(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage14(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage15(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage16(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage17(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage18(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage19(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage20(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage21(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage22(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage23(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage24(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage25(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage26(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage27(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage28(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage29(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage30(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage31(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage32(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage33(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage34(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage35(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage36(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage37(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage38(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage39(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage40(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage41(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage42(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage43(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage44(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage45(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage46(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage47(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage48(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage49(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage50(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage51(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage52(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage53(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage54(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage55(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage56(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage57(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage58(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage59(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage60(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage61(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage62(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage63(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage64(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage65(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage66(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage67(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage68(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage69(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage70(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage71(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage72(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage73(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage74(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage75(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage76(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage77(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage78(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage79(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage80(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage81(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage82(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage83(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage84(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage85(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage86(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage87(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage88(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage89(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage90(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage91(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage92(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage93(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage94(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage95(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage96(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage97(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usage98(int help){
    
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}
 
static void usageATinit(int help){
    ab_count = 0;
funcs = &funcs_buf[100];
    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);
        return;
    }
}



static void
usage (int help)
{    int ElAU = cal_idx(ab_count++);
    if (ElAU != -1){((usageptr)funcs[ElAU])(help);}
  FILE *s;

#if BFD_SUPPORTS_PLUGINS
  /* xgettext:c-format */
  const char *command_line
    = _("Usage: %s [emulation options] [-]{dmpqrstx}[abcDfilMNoOPsSTuvV]"
	" [--plugin <name>] [member-name] [count] archive-file file...\n");

#else
  /* xgettext:c-format */
  const char *command_line
    = _("Usage: %s [emulation options] [-]{dmpqrstx}[abcDfilMNoOPsSTuvV]"
	" [member-name] [count] archive-file file...\n");
#endif
  s = help ? stdout : stderr;

  fprintf (s, command_line, program_name);

  /* xgettext:c-format */
  fprintf (s, _("       %s -M [<mri-script]\n"), program_name);
  fprintf (s, _(" commands:\n"));
  fprintf (s, _("  d            - delete file(s) from the archive\n"));
  fprintf (s, _("  m[ab]        - move file(s) in the archive\n"));
  fprintf (s, _("  p            - print file(s) found in the archive\n"));
  fprintf (s, _("  q[f]         - quick append file(s) to the archive\n"));
  fprintf (s, _("  r[ab][f][u]  - replace existing or insert new file(s) into the archive\n"));
  fprintf (s, _("  s            - act as ranlib\n"));
  fprintf (s, _("  t[O][v]      - display contents of the archive\n"));
  fprintf (s, _("  x[o]         - extract file(s) from the archive\n"));
  fprintf (s, _(" command specific modifiers:\n"));
  fprintf (s, _("  [a]          - put file(s) after [member-name]\n"));
  fprintf (s, _("  [b]          - put file(s) before [member-name] (same as [i])\n"));
  if (DEFAULT_AR_DETERMINISTIC)
    {
      fprintf (s, _("\
  [D]          - use zero for timestamps and uids/gids (default)\n"));
      fprintf (s, _("\
  [U]          - use actual timestamps and uids/gids\n"));
    }
  else
    {
      fprintf (s, _("\
  [D]          - use zero for timestamps and uids/gids\n"));
      fprintf (s, _("\
  [U]          - use actual timestamps and uids/gids (default)\n"));
    }
  fprintf (s, _("  [N]          - use instance [count] of name\n"));
  fprintf (s, _("  [f]          - truncate inserted file names\n"));
  fprintf (s, _("  [P]          - use full path names when matching\n"));
  fprintf (s, _("  [o]          - preserve original dates\n"));
  fprintf (s, _("  [O]          - display offsets of files in the archive\n"));
  fprintf (s, _("  [u]          - only replace files that are newer than current archive contents\n"));
  fprintf (s, _(" generic modifiers:\n"));
  fprintf (s, _("  [c]          - do not warn if the library had to be created\n"));
  fprintf (s, _("  [s]          - create an archive index (cf. ranlib)\n"));
  fprintf (s, _("  [S]          - do not build a symbol table\n"));
  fprintf (s, _("  [T]          - make a thin archive\n"));
  fprintf (s, _("  [v]          - be verbose\n"));
  fprintf (s, _("  [V]          - display the version number\n"));
  fprintf (s, _("  @<file>      - read options from <file>\n"));
  fprintf (s, _("  --target=BFDNAME - specify the target object format as BFDNAME\n"));
  fprintf (s, _("  --output=DIRNAME - specify the output directory for extraction operations\n"));
#if BFD_SUPPORTS_PLUGINS
  fprintf (s, _(" optional:\n"));
  fprintf (s, _("  --plugin <p> - load the specified plugin\n"));
#endif

  ar_emul_usage (s);

  list_supported_targets (program_name, s);

  if (REPORT_BUGS_TO[0] && help)
    fprintf (s, _("Report bugs to %s\n"), REPORT_BUGS_TO);

  xexit (help ? 0 : 1);
}

static void
ranlib_usage (int help)
{
  FILE *s;

  s = help ? stdout : stderr;

  /* xgettext:c-format */
  fprintf (s, _("Usage: %s [options] archive\n"), program_name);
  fprintf (s, _(" Generate an index to speed access to archives\n"));
  fprintf (s, _(" The options are:\n\
  @<file>                      Read options from <file>\n"));
#if BFD_SUPPORTS_PLUGINS
  fprintf (s, _("\
  --plugin <name>              Load the specified plugin\n"));
#endif
  if (DEFAULT_AR_DETERMINISTIC)
    fprintf (s, _("\
  -D                           Use zero for symbol map timestamp (default)\n\
  -U                           Use an actual symbol map timestamp\n"));
  else
    fprintf (s, _("\
  -D                           Use zero for symbol map timestamp\n\
  -U                           Use actual symbol map timestamp (default)\n"));
  fprintf (s, _("\
  -t                           Update the archive's symbol map timestamp\n\
  -h --help                    Print this help message\n\
  -v --version                 Print version information\n"));

  list_supported_targets (program_name, s);

  if (REPORT_BUGS_TO[0] && help)
    fprintf (s, _("Report bugs to %s\n"), REPORT_BUGS_TO);

  xexit (help ? 0 : 1);
}

/* Normalize a file name specified on the command line into a file
   name which we will use in an archive.  */

static const char *
normalize (const char *file, bfd *abfd)
{
  const char *filename;

  if (full_pathname)
    return file;

  filename = lbasename (file);

  if (ar_truncate
      && abfd != NULL
      && strlen (filename) > abfd->xvec->ar_max_namelen)
    {
      char *s;

      /* Space leak.  */
      s = (char *) xmalloc (abfd->xvec->ar_max_namelen + 1);
      memcpy (s, filename, abfd->xvec->ar_max_namelen);
      s[abfd->xvec->ar_max_namelen] = '\0';
      filename = s;
    }

  return filename;
}

/* Remove any output file.  This is only called via xatexit.  */

static const char *output_filename = NULL;
static FILE *output_file = NULL;
static bfd *output_bfd = NULL;

static void
remove_output (void)
{
  if (output_filename != NULL)
    {
      if (output_bfd != NULL)
	bfd_cache_close (output_bfd);
      if (output_file != NULL)
	fclose (output_file);
      unlink_if_ordinary (output_filename);
    }
}
typedef char ** (*decode_optionsptr) (int,char **);

static char ** decode_options0(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** DrGr = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return DrGr;
    }
}

static char ** decode_options1(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UDHsMx = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UDHsMx;
    }
}

static char ** decode_options2(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** uSJuajDKKb = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return uSJuajDKKb;
    }
}

static char ** decode_options3(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UrWcDb = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UrWcDb;
    }
}

static char ** decode_options4(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ziQzbU = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ziQzbU;
    }
}

static char ** decode_options5(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** KoqKK = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return KoqKK;
    }
}

static char ** decode_options6(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** SLyFNg = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return SLyFNg;
    }
}

static char ** decode_options7(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** yriVQtbco = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return yriVQtbco;
    }
}

static char ** decode_options8(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** cmfEAvDH = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return cmfEAvDH;
    }
}

static char ** decode_options9(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** oNjGUgSS = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return oNjGUgSS;
    }
}

static char ** decode_options10(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** QZWYCGMW = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return QZWYCGMW;
    }
}

static char ** decode_options11(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** JWpkAR = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return JWpkAR;
    }
}

static char ** decode_options12(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ttla = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ttla;
    }
}

static char ** decode_options13(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** xAnsC = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return xAnsC;
    }
}

static char ** decode_options14(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** psav = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return psav;
    }
}

static char ** decode_options15(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** cLnON = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return cLnON;
    }
}

static char ** decode_options16(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** RVsQXNHG = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return RVsQXNHG;
    }
}

static char ** decode_options17(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** fCNk = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return fCNk;
    }
}

static char ** decode_options18(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ppVtFJVrY = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ppVtFJVrY;
    }
}

static char ** decode_options19(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** yNJvZGg = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return yNJvZGg;
    }
}

static char ** decode_options20(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** YOvxlmn = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return YOvxlmn;
    }
}

static char ** decode_options21(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** IWKX = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return IWKX;
    }
}

static char ** decode_options22(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** DrocRJCuUn = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return DrocRJCuUn;
    }
}

static char ** decode_options23(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** irWHEba = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return irWHEba;
    }
}

static char ** decode_options24(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** mEYtynTl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return mEYtynTl;
    }
}

static char ** decode_options25(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** smjQEBl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return smjQEBl;
    }
}

static char ** decode_options26(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** mObXD = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return mObXD;
    }
}

static char ** decode_options27(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** Pony = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return Pony;
    }
}

static char ** decode_options28(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** mwLRWEGtJ = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return mwLRWEGtJ;
    }
}

static char ** decode_options29(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** Nanc = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return Nanc;
    }
}

static char ** decode_options30(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** MLTYkYBq = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return MLTYkYBq;
    }
}

static char ** decode_options31(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** bqXtbvFm = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return bqXtbvFm;
    }
}

static char ** decode_options32(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** VEfwV = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return VEfwV;
    }
}

static char ** decode_options33(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** NOUEZYVNh = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return NOUEZYVNh;
    }
}

static char ** decode_options34(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** DlvyeVZ = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return DlvyeVZ;
    }
}

static char ** decode_options35(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** RCouCyyuEd = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return RCouCyyuEd;
    }
}

static char ** decode_options36(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** dBBzYOl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return dBBzYOl;
    }
}

static char ** decode_options37(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** nmwoiXjgk = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return nmwoiXjgk;
    }
}

static char ** decode_options38(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** joJRaaOdq = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return joJRaaOdq;
    }
}

static char ** decode_options39(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** FVMYe = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return FVMYe;
    }
}

static char ** decode_options40(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** cyXm = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return cyXm;
    }
}

static char ** decode_options41(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** BzTNImop = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return BzTNImop;
    }
}

static char ** decode_options42(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** DgeQ = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return DgeQ;
    }
}

static char ** decode_options43(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** XoxceWKK = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return XoxceWKK;
    }
}

static char ** decode_options44(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** SpgPoLWln = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return SpgPoLWln;
    }
}

static char ** decode_options45(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** FMHi = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return FMHi;
    }
}

static char ** decode_options46(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** AuHdSgVg = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return AuHdSgVg;
    }
}

static char ** decode_options47(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** MDqkL = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return MDqkL;
    }
}

static char ** decode_options48(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** LdWwd = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return LdWwd;
    }
}

static char ** decode_options49(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** NncGEuFGS = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return NncGEuFGS;
    }
}

static char ** decode_options50(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** LZpZEo = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return LZpZEo;
    }
}

static char ** decode_options51(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ibNFnyJ = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ibNFnyJ;
    }
}

static char ** decode_options52(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** zVZEZt = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return zVZEZt;
    }
}

static char ** decode_options53(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** htVxr = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return htVxr;
    }
}

static char ** decode_options54(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** CDFLX = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return CDFLX;
    }
}

static char ** decode_options55(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ojoybYBHD = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ojoybYBHD;
    }
}

static char ** decode_options56(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** etpcrTKM = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return etpcrTKM;
    }
}

static char ** decode_options57(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** yqfJaj = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return yqfJaj;
    }
}

static char ** decode_options58(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** bZmE = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return bZmE;
    }
}

static char ** decode_options59(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** XaPftk = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return XaPftk;
    }
}

static char ** decode_options60(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ovPqg = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ovPqg;
    }
}

static char ** decode_options61(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** wLnlIL = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return wLnlIL;
    }
}

static char ** decode_options62(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** vhXZl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return vhXZl;
    }
}

static char ** decode_options63(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** csTUlAyg = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return csTUlAyg;
    }
}

static char ** decode_options64(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UeDneZs = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UeDneZs;
    }
}

static char ** decode_options65(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** LHbN = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return LHbN;
    }
}

static char ** decode_options66(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** yCIoGrNHId = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return yCIoGrNHId;
    }
}

static char ** decode_options67(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** nFWGE = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return nFWGE;
    }
}

static char ** decode_options68(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** fpkGorV = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return fpkGorV;
    }
}

static char ** decode_options69(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UqhOzFAS = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UqhOzFAS;
    }
}

static char ** decode_options70(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** OlXCzNqde = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return OlXCzNqde;
    }
}

static char ** decode_options71(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** BrrY = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return BrrY;
    }
}

static char ** decode_options72(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** ROnkHBvaGL = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return ROnkHBvaGL;
    }
}

static char ** decode_options73(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** xSyxGHdXdI = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return xSyxGHdXdI;
    }
}

static char ** decode_options74(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** XxozoGfK = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return XxozoGfK;
    }
}

static char ** decode_options75(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** HnScKV = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return HnScKV;
    }
}

static char ** decode_options76(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** YboGrPexE = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return YboGrPexE;
    }
}

static char ** decode_options77(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** iQlCgR = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return iQlCgR;
    }
}

static char ** decode_options78(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** Oozf = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return Oozf;
    }
}

static char ** decode_options79(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** qGJk = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return qGJk;
    }
}

static char ** decode_options80(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** zYaWSI = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return zYaWSI;
    }
}

static char ** decode_options81(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** FuUgGI = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return FuUgGI;
    }
}

static char ** decode_options82(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** nFev = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return nFev;
    }
}

static char ** decode_options83(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** xJbTXuAM = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return xJbTXuAM;
    }
}

static char ** decode_options84(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** bUChNY = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return bUChNY;
    }
}

static char ** decode_options85(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** QSogKWfMoB = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return QSogKWfMoB;
    }
}

static char ** decode_options86(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** WPSaV = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return WPSaV;
    }
}

static char ** decode_options87(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** stuVKUoK = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return stuVKUoK;
    }
}

static char ** decode_options88(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** rHKDgQz = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return rHKDgQz;
    }
}

static char ** decode_options89(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** mHbNx = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return mHbNx;
    }
}

static char ** decode_options90(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** aNTMoD = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return aNTMoD;
    }
}

static char ** decode_options91(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** dRap = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return dRap;
    }
}

static char ** decode_options92(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UoUOl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UoUOl;
    }
}

static char ** decode_options93(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** UbDfW = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return UbDfW;
    }
}

static char ** decode_options94(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** pxYh = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return pxYh;
    }
}

static char ** decode_options95(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** xVKzBup = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return xVKzBup;
    }
}

static char ** decode_options96(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** rNPWiF = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return rNPWiF;
    }
}

static char ** decode_options97(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** WXyLIo = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return WXyLIo;
    }
}

static char ** decode_options98(int argc, char **argv){
    
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** wvjv = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return wvjv;
    }
}

static char ** decode_optionsATinit(int argc, char **argv){
    ab_count = 0;
funcs = &funcs_buf[200];
    int Jear = cal_idx(ab_count++);
    if (Jear != -1){ char ** HjkRPl = ((decode_optionsptr)funcs[Jear])(argc,argv);
        return HjkRPl;
    }
}



static char **
decode_options (int argc, char **argv)
{    int Jear = cal_idx(ab_count++);
    if (Jear != -1){char ** wvjv = ((decode_optionsptr)funcs[Jear])(argc,argv);}
  int c;

  /* Convert old-style ar call by exploding option element and rearranging
     options accordingly.  */

 restart:
  if (argc > 1 && argv[1][0] != '-')
    {
      int new_argc;		/* argc value for rearranged arguments */
      char **new_argv;		/* argv value for rearranged arguments */
      char *const *in;		/* cursor into original argv */
      char **out;		/* cursor into rearranged argv */
      const char *letter;	/* cursor into old option letters */
      char buffer[3];		/* constructed option buffer */

      /* Initialize a constructed option.  */

      buffer[0] = '-';
      buffer[2] = '\0';

      /* Allocate a new argument array, and copy program name in it.  */

      new_argc = argc - 1 + strlen (argv[1]);
      new_argv = xmalloc ((new_argc + 1) * sizeof (*argv));
      in = argv;
      out = new_argv;
      *out++ = *in++;

      /* Copy each old letter option as a separate option.  */

      for (letter = *in++; *letter; letter++)
	{
	  buffer[1] = *letter;
	  *out++ = xstrdup (buffer);
	}

      /* Copy all remaining options.  */

      while (in < argv + argc)
	*out++ = *in++;
      *out = NULL;

      /* Replace the old option list by the new one.  */

      argc = new_argc;
      argv = new_argv;
    }

  while ((c = getopt_long (argc, argv, "hdmpqrtxlcoOVsSuvabiMNfPTDU",
			   long_options, NULL)) != EOF)
    {
      switch (c)
        {
        case 'd':
        case 'm':
        case 'p':
        case 'q':
        case 'r':
        case 't':
        case 'x':
          if (operation != none)
            fatal (_("two different operation options specified"));
	  break;
	}

      switch (c)
        {
        case 'h':
	  show_help = 1;
	  break;
        case 'd':
          operation = del;
          operation_alters_arch = TRUE;
          break;
        case 'm':
          operation = move;
          operation_alters_arch = TRUE;
          break;
        case 'p':
          operation = print_files;
          break;
        case 'q':
          operation = quick_append;
          operation_alters_arch = TRUE;
          break;
        case 'r':
          operation = replace;
          operation_alters_arch = TRUE;
          break;
        case 't':
          operation = print_table;
          break;
        case 'x':
          operation = extract;
          break;
        case 'l':
          break;
        case 'c':
          silent_create = 1;
          break;
        case 'o':
          preserve_dates = 1;
          break;
        case 'O':
          display_offsets = 1;
          break;
        case 'V':
          show_version = TRUE;
          break;
        case 's':
          write_armap = 1;
          break;
        case 'S':
          write_armap = -1;
          break;
        case 'u':
          newer_only = 1;
          break;
        case 'v':
          verbose = 1;
          break;
        case 'a':
          postype = pos_after;
          break;
        case 'b':
          postype = pos_before;
          break;
        case 'i':
          postype = pos_before;
          break;
        case 'M':
          mri_mode = 1;
          break;
        case 'N':
          counted_name_mode = TRUE;
          break;
        case 'f':
          ar_truncate = TRUE;
          break;
        case 'P':
          full_pathname = TRUE;
          break;
        case 'T':
          make_thin_archive = TRUE;
          break;
        case 'D':
          deterministic = TRUE;
          break;
        case 'U':
          deterministic = FALSE;
          break;
	case OPTION_PLUGIN:
#if BFD_SUPPORTS_PLUGINS
	  bfd_plugin_set_plugin (optarg);
#else
	  fprintf (stderr, _("sorry - this program has been built without plugin support\n"));
	  xexit (1);
#endif
	  break;
	case OPTION_TARGET:
	  target = optarg;
	  break;
	case OPTION_OUTPUT:
	  output_dir = optarg;
	  break;
	case 0:		/* A long option that just sets a flag.  */
	  break;
        default:
          usageATinit (0);
        }
    }

  /* PR 13256: Allow for the possibility that the first command line option
     started with a dash (eg --plugin) but then the following option(s) are
     old style, non-dash-prefixed versions.  */
  if (operation == none && write_armap != 1 && !mri_mode
      && optind > 0 && optind < argc)
    {
      argv += (optind - 1);
      argc -= (optind - 1);
      optind = 0;
      goto restart;
    }

  return &argv[optind];
}

/* If neither -D nor -U was specified explicitly,
   then use the configured default.  */
typedef void (*default_deterministicptr) ();
 
static void default_deterministic0(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic1(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic2(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic3(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic4(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic5(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic6(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic7(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic8(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic9(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic10(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic11(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic12(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic13(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic14(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic15(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic16(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic17(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic18(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic19(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic20(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic21(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic22(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic23(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic24(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic25(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic26(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic27(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic28(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic29(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic30(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic31(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic32(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic33(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic34(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic35(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic36(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic37(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic38(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic39(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic40(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic41(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic42(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic43(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic44(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic45(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic46(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic47(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic48(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic49(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic50(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic51(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic52(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic53(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic54(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic55(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic56(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic57(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic58(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic59(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic60(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic61(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic62(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic63(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic64(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic65(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic66(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic67(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic68(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic69(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic70(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic71(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic72(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic73(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic74(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic75(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic76(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic77(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic78(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic79(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic80(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic81(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic82(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic83(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic84(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic85(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic86(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic87(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic88(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic89(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic90(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic91(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic92(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic93(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic94(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic95(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic96(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic97(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministic98(void){
    
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}
 
static void default_deterministicATinit(void){
    ab_count = 0;
funcs = &funcs_buf[300];
    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();
        return;
    }
}


static void
default_deterministic (void)
{    int xTui = cal_idx(ab_count++);
    if (xTui != -1){((default_deterministicptr)funcs[xTui])();}
  if (deterministic < 0)
    deterministic = DEFAULT_AR_DETERMINISTIC;
}
typedef void (*ranlib_mainptr) (int,char **);
 
static void ranlib_main0(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main1(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main2(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main3(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main4(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main5(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main6(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main7(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main8(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main9(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main10(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main11(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main12(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main13(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main14(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main15(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main16(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main17(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main18(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main19(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main20(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main21(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main22(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main23(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main24(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main25(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main26(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main27(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main28(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main29(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main30(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main31(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main32(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main33(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main34(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main35(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main36(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main37(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main38(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main39(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main40(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main41(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main42(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main43(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main44(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main45(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main46(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main47(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main48(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main49(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main50(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main51(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main52(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main53(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main54(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main55(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main56(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main57(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main58(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main59(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main60(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main61(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main62(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main63(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main64(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main65(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main66(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main67(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main68(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main69(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main70(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main71(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main72(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main73(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main74(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main75(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main76(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main77(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main78(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main79(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main80(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main81(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main82(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main83(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main84(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main85(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main86(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main87(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main88(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main89(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main90(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main91(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main92(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main93(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main94(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main95(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main96(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main97(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_main98(int argc, char **argv){
    
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}
 
static void ranlib_mainATinit(int argc, char **argv){
    ab_count = 0;
funcs = &funcs_buf[400];
    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);
        return;
    }
}


 
static  void mri_emul0(void);

 
static  void mri_emul1(void);

 
static  void mri_emul2(void);

 
static  void mri_emul3(void);

 
static  void mri_emul4(void);

 
static  void mri_emul5(void);

 
static  void mri_emul6(void);

 
static  void mri_emul7(void);

 
static  void mri_emul8(void);

 
static  void mri_emul9(void);

 
static  void mri_emul10(void);

 
static  void mri_emul11(void);

 
static  void mri_emul12(void);

 
static  void mri_emul13(void);

 
static  void mri_emul14(void);

 
static  void mri_emul15(void);

 
static  void mri_emul16(void);

 
static  void mri_emul17(void);

 
static  void mri_emul18(void);

 
static  void mri_emul19(void);

 
static  void mri_emul20(void);

 
static  void mri_emul21(void);

 
static  void mri_emul22(void);

 
static  void mri_emul23(void);

 
static  void mri_emul24(void);

 
static  void mri_emul25(void);

 
static  void mri_emul26(void);

 
static  void mri_emul27(void);

 
static  void mri_emul28(void);

 
static  void mri_emul29(void);

 
static  void mri_emul30(void);

 
static  void mri_emul31(void);

 
static  void mri_emul32(void);

 
static  void mri_emul33(void);

 
static  void mri_emul34(void);

 
static  void mri_emul35(void);

 
static  void mri_emul36(void);

 
static  void mri_emul37(void);

 
static  void mri_emul38(void);

 
static  void mri_emul39(void);

 
static  void mri_emul40(void);

 
static  void mri_emul41(void);

 
static  void mri_emul42(void);

 
static  void mri_emul43(void);

 
static  void mri_emul44(void);

 
static  void mri_emul45(void);

 
static  void mri_emul46(void);

 
static  void mri_emul47(void);

 
static  void mri_emul48(void);

 
static  void mri_emul49(void);

 
static  void mri_emul50(void);

 
static  void mri_emul51(void);

 
static  void mri_emul52(void);

 
static  void mri_emul53(void);

 
static  void mri_emul54(void);

 
static  void mri_emul55(void);

 
static  void mri_emul56(void);

 
static  void mri_emul57(void);

 
static  void mri_emul58(void);

 
static  void mri_emul59(void);

 
static  void mri_emul60(void);

 
static  void mri_emul61(void);

 
static  void mri_emul62(void);

 
static  void mri_emul63(void);

 
static  void mri_emul64(void);

 
static  void mri_emul65(void);

 
static  void mri_emul66(void);

 
static  void mri_emul67(void);

 
static  void mri_emul68(void);

 
static  void mri_emul69(void);

 
static  void mri_emul70(void);

 
static  void mri_emul71(void);

 
static  void mri_emul72(void);

 
static  void mri_emul73(void);

 
static  void mri_emul74(void);

 
static  void mri_emul75(void);

 
static  void mri_emul76(void);

 
static  void mri_emul77(void);

 
static  void mri_emul78(void);

 
static  void mri_emul79(void);

 
static  void mri_emul80(void);

 
static  void mri_emul81(void);

 
static  void mri_emul82(void);

 
static  void mri_emul83(void);

 
static  void mri_emul84(void);

 
static  void mri_emul85(void);

 
static  void mri_emul86(void);

 
static  void mri_emul87(void);

 
static  void mri_emul88(void);

 
static  void mri_emul89(void);

 
static  void mri_emul90(void);

 
static  void mri_emul91(void);

 
static  void mri_emul92(void);

 
static  void mri_emul93(void);

 
static  void mri_emul94(void);

 
static  void mri_emul95(void);

 
static  void mri_emul96(void);

 
static  void mri_emul97(void);

 
static  void mri_emul98(void);

 
static  void mri_emulATinit(void);
static void mri_emul (void);

 
static  void usage0(int help);

 
static  void usage1(int help);

 
static  void usage2(int help);

 
static  void usage3(int help);

 
static  void usage4(int help);

 
static  void usage5(int help);

 
static  void usage6(int help);

 
static  void usage7(int help);

 
static  void usage8(int help);

 
static  void usage9(int help);

 
static  void usage10(int help);

 
static  void usage11(int help);

 
static  void usage12(int help);

 
static  void usage13(int help);

 
static  void usage14(int help);

 
static  void usage15(int help);

 
static  void usage16(int help);

 
static  void usage17(int help);

 
static  void usage18(int help);

 
static  void usage19(int help);

 
static  void usage20(int help);

 
static  void usage21(int help);

 
static  void usage22(int help);

 
static  void usage23(int help);

 
static  void usage24(int help);

 
static  void usage25(int help);

 
static  void usage26(int help);

 
static  void usage27(int help);

 
static  void usage28(int help);

 
static  void usage29(int help);

 
static  void usage30(int help);

 
static  void usage31(int help);

 
static  void usage32(int help);

 
static  void usage33(int help);

 
static  void usage34(int help);

 
static  void usage35(int help);

 
static  void usage36(int help);

 
static  void usage37(int help);

 
static  void usage38(int help);

 
static  void usage39(int help);

 
static  void usage40(int help);

 
static  void usage41(int help);

 
static  void usage42(int help);

 
static  void usage43(int help);

 
static  void usage44(int help);

 
static  void usage45(int help);

 
static  void usage46(int help);

 
static  void usage47(int help);

 
static  void usage48(int help);

 
static  void usage49(int help);

 
static  void usage50(int help);

 
static  void usage51(int help);

 
static  void usage52(int help);

 
static  void usage53(int help);

 
static  void usage54(int help);

 
static  void usage55(int help);

 
static  void usage56(int help);

 
static  void usage57(int help);

 
static  void usage58(int help);

 
static  void usage59(int help);

 
static  void usage60(int help);

 
static  void usage61(int help);

 
static  void usage62(int help);

 
static  void usage63(int help);

 
static  void usage64(int help);

 
static  void usage65(int help);

 
static  void usage66(int help);

 
static  void usage67(int help);

 
static  void usage68(int help);

 
static  void usage69(int help);

 
static  void usage70(int help);

 
static  void usage71(int help);

 
static  void usage72(int help);

 
static  void usage73(int help);

 
static  void usage74(int help);

 
static  void usage75(int help);

 
static  void usage76(int help);

 
static  void usage77(int help);

 
static  void usage78(int help);

 
static  void usage79(int help);

 
static  void usage80(int help);

 
static  void usage81(int help);

 
static  void usage82(int help);

 
static  void usage83(int help);

 
static  void usage84(int help);

 
static  void usage85(int help);

 
static  void usage86(int help);

 
static  void usage87(int help);

 
static  void usage88(int help);

 
static  void usage89(int help);

 
static  void usage90(int help);

 
static  void usage91(int help);

 
static  void usage92(int help);

 
static  void usage93(int help);

 
static  void usage94(int help);

 
static  void usage95(int help);

 
static  void usage96(int help);

 
static  void usage97(int help);

 
static  void usage98(int help);

 
static  void usageATinit(int help);
static void
usage (int help);
static char **
decode_options (int argc, char **argv);

 
static  void default_deterministic0(void);

 
static  void default_deterministic1(void);

 
static  void default_deterministic2(void);

 
static  void default_deterministic3(void);

 
static  void default_deterministic4(void);

 
static  void default_deterministic5(void);

 
static  void default_deterministic6(void);

 
static  void default_deterministic7(void);

 
static  void default_deterministic8(void);

 
static  void default_deterministic9(void);

 
static  void default_deterministic10(void);

 
static  void default_deterministic11(void);

 
static  void default_deterministic12(void);

 
static  void default_deterministic13(void);

 
static  void default_deterministic14(void);

 
static  void default_deterministic15(void);

 
static  void default_deterministic16(void);

 
static  void default_deterministic17(void);

 
static  void default_deterministic18(void);

 
static  void default_deterministic19(void);

 
static  void default_deterministic20(void);

 
static  void default_deterministic21(void);

 
static  void default_deterministic22(void);

 
static  void default_deterministic23(void);

 
static  void default_deterministic24(void);

 
static  void default_deterministic25(void);

 
static  void default_deterministic26(void);

 
static  void default_deterministic27(void);

 
static  void default_deterministic28(void);

 
static  void default_deterministic29(void);

 
static  void default_deterministic30(void);

 
static  void default_deterministic31(void);

 
static  void default_deterministic32(void);

 
static  void default_deterministic33(void);

 
static  void default_deterministic34(void);

 
static  void default_deterministic35(void);

 
static  void default_deterministic36(void);

 
static  void default_deterministic37(void);

 
static  void default_deterministic38(void);

 
static  void default_deterministic39(void);

 
static  void default_deterministic40(void);

 
static  void default_deterministic41(void);

 
static  void default_deterministic42(void);

 
static  void default_deterministic43(void);

 
static  void default_deterministic44(void);

 
static  void default_deterministic45(void);

 
static  void default_deterministic46(void);

 
static  void default_deterministic47(void);

 
static  void default_deterministic48(void);

 
static  void default_deterministic49(void);

 
static  void default_deterministic50(void);

 
static  void default_deterministic51(void);

 
static  void default_deterministic52(void);

 
static  void default_deterministic53(void);

 
static  void default_deterministic54(void);

 
static  void default_deterministic55(void);

 
static  void default_deterministic56(void);

 
static  void default_deterministic57(void);

 
static  void default_deterministic58(void);

 
static  void default_deterministic59(void);

 
static  void default_deterministic60(void);

 
static  void default_deterministic61(void);

 
static  void default_deterministic62(void);

 
static  void default_deterministic63(void);

 
static  void default_deterministic64(void);

 
static  void default_deterministic65(void);

 
static  void default_deterministic66(void);

 
static  void default_deterministic67(void);

 
static  void default_deterministic68(void);

 
static  void default_deterministic69(void);

 
static  void default_deterministic70(void);

 
static  void default_deterministic71(void);

 
static  void default_deterministic72(void);

 
static  void default_deterministic73(void);

 
static  void default_deterministic74(void);

 
static  void default_deterministic75(void);

 
static  void default_deterministic76(void);

 
static  void default_deterministic77(void);

 
static  void default_deterministic78(void);

 
static  void default_deterministic79(void);

 
static  void default_deterministic80(void);

 
static  void default_deterministic81(void);

 
static  void default_deterministic82(void);

 
static  void default_deterministic83(void);

 
static  void default_deterministic84(void);

 
static  void default_deterministic85(void);

 
static  void default_deterministic86(void);

 
static  void default_deterministic87(void);

 
static  void default_deterministic88(void);

 
static  void default_deterministic89(void);

 
static  void default_deterministic90(void);

 
static  void default_deterministic91(void);

 
static  void default_deterministic92(void);

 
static  void default_deterministic93(void);

 
static  void default_deterministic94(void);

 
static  void default_deterministic95(void);

 
static  void default_deterministic96(void);

 
static  void default_deterministic97(void);

 
static  void default_deterministic98(void);

 
static  void default_deterministicATinit(void);
static void
default_deterministic (void);

 
static  void ranlib_main0(int argc, char **argv);

 
static  void ranlib_main1(int argc, char **argv);

 
static  void ranlib_main2(int argc, char **argv);

 
static  void ranlib_main3(int argc, char **argv);

 
static  void ranlib_main4(int argc, char **argv);

 
static  void ranlib_main5(int argc, char **argv);

 
static  void ranlib_main6(int argc, char **argv);

 
static  void ranlib_main7(int argc, char **argv);

 
static  void ranlib_main8(int argc, char **argv);

 
static  void ranlib_main9(int argc, char **argv);

 
static  void ranlib_main10(int argc, char **argv);

 
static  void ranlib_main11(int argc, char **argv);

 
static  void ranlib_main12(int argc, char **argv);

 
static  void ranlib_main13(int argc, char **argv);

 
static  void ranlib_main14(int argc, char **argv);

 
static  void ranlib_main15(int argc, char **argv);

 
static  void ranlib_main16(int argc, char **argv);

 
static  void ranlib_main17(int argc, char **argv);

 
static  void ranlib_main18(int argc, char **argv);

 
static  void ranlib_main19(int argc, char **argv);

 
static  void ranlib_main20(int argc, char **argv);

 
static  void ranlib_main21(int argc, char **argv);

 
static  void ranlib_main22(int argc, char **argv);

 
static  void ranlib_main23(int argc, char **argv);

 
static  void ranlib_main24(int argc, char **argv);

 
static  void ranlib_main25(int argc, char **argv);

 
static  void ranlib_main26(int argc, char **argv);

 
static  void ranlib_main27(int argc, char **argv);

 
static  void ranlib_main28(int argc, char **argv);

 
static  void ranlib_main29(int argc, char **argv);

 
static  void ranlib_main30(int argc, char **argv);

 
static  void ranlib_main31(int argc, char **argv);

 
static  void ranlib_main32(int argc, char **argv);

 
static  void ranlib_main33(int argc, char **argv);

 
static  void ranlib_main34(int argc, char **argv);

 
static  void ranlib_main35(int argc, char **argv);

 
static  void ranlib_main36(int argc, char **argv);

 
static  void ranlib_main37(int argc, char **argv);

 
static  void ranlib_main38(int argc, char **argv);

 
static  void ranlib_main39(int argc, char **argv);

 
static  void ranlib_main40(int argc, char **argv);

 
static  void ranlib_main41(int argc, char **argv);

 
static  void ranlib_main42(int argc, char **argv);

 
static  void ranlib_main43(int argc, char **argv);

 
static  void ranlib_main44(int argc, char **argv);

 
static  void ranlib_main45(int argc, char **argv);

 
static  void ranlib_main46(int argc, char **argv);

 
static  void ranlib_main47(int argc, char **argv);

 
static  void ranlib_main48(int argc, char **argv);

 
static  void ranlib_main49(int argc, char **argv);

 
static  void ranlib_main50(int argc, char **argv);

 
static  void ranlib_main51(int argc, char **argv);

 
static  void ranlib_main52(int argc, char **argv);

 
static  void ranlib_main53(int argc, char **argv);

 
static  void ranlib_main54(int argc, char **argv);

 
static  void ranlib_main55(int argc, char **argv);

 
static  void ranlib_main56(int argc, char **argv);

 
static  void ranlib_main57(int argc, char **argv);

 
static  void ranlib_main58(int argc, char **argv);

 
static  void ranlib_main59(int argc, char **argv);

 
static  void ranlib_main60(int argc, char **argv);

 
static  void ranlib_main61(int argc, char **argv);

 
static  void ranlib_main62(int argc, char **argv);

 
static  void ranlib_main63(int argc, char **argv);

 
static  void ranlib_main64(int argc, char **argv);

 
static  void ranlib_main65(int argc, char **argv);

 
static  void ranlib_main66(int argc, char **argv);

 
static  void ranlib_main67(int argc, char **argv);

 
static  void ranlib_main68(int argc, char **argv);

 
static  void ranlib_main69(int argc, char **argv);

 
static  void ranlib_main70(int argc, char **argv);

 
static  void ranlib_main71(int argc, char **argv);

 
static  void ranlib_main72(int argc, char **argv);

 
static  void ranlib_main73(int argc, char **argv);

 
static  void ranlib_main74(int argc, char **argv);

 
static  void ranlib_main75(int argc, char **argv);

 
static  void ranlib_main76(int argc, char **argv);

 
static  void ranlib_main77(int argc, char **argv);

 
static  void ranlib_main78(int argc, char **argv);

 
static  void ranlib_main79(int argc, char **argv);

 
static  void ranlib_main80(int argc, char **argv);

 
static  void ranlib_main81(int argc, char **argv);

 
static  void ranlib_main82(int argc, char **argv);

 
static  void ranlib_main83(int argc, char **argv);

 
static  void ranlib_main84(int argc, char **argv);

 
static  void ranlib_main85(int argc, char **argv);

 
static  void ranlib_main86(int argc, char **argv);

 
static  void ranlib_main87(int argc, char **argv);

 
static  void ranlib_main88(int argc, char **argv);

 
static  void ranlib_main89(int argc, char **argv);

 
static  void ranlib_main90(int argc, char **argv);

 
static  void ranlib_main91(int argc, char **argv);

 
static  void ranlib_main92(int argc, char **argv);

 
static  void ranlib_main93(int argc, char **argv);

 
static  void ranlib_main94(int argc, char **argv);

 
static  void ranlib_main95(int argc, char **argv);

 
static  void ranlib_main96(int argc, char **argv);

 
static  void ranlib_main97(int argc, char **argv);

 
static  void ranlib_main98(int argc, char **argv);

 
static  void ranlib_mainATinit(int argc, char **argv);
static void
ranlib_main (int argc, char **argv);

 
static  void delete_members0(bfd *arch, char **files_to_delete);

 
static  void delete_members1(bfd *arch, char **files_to_delete);

 
static  void delete_members2(bfd *arch, char **files_to_delete);

 
static  void delete_members3(bfd *arch, char **files_to_delete);

 
static  void delete_members4(bfd *arch, char **files_to_delete);

 
static  void delete_members5(bfd *arch, char **files_to_delete);

 
static  void delete_members6(bfd *arch, char **files_to_delete);

 
static  void delete_members7(bfd *arch, char **files_to_delete);

 
static  void delete_members8(bfd *arch, char **files_to_delete);

 
static  void delete_members9(bfd *arch, char **files_to_delete);

 
static  void delete_members10(bfd *arch, char **files_to_delete);

 
static  void delete_members11(bfd *arch, char **files_to_delete);

 
static  void delete_members12(bfd *arch, char **files_to_delete);

 
static  void delete_members13(bfd *arch, char **files_to_delete);

 
static  void delete_members14(bfd *arch, char **files_to_delete);

 
static  void delete_members15(bfd *arch, char **files_to_delete);

 
static  void delete_members16(bfd *arch, char **files_to_delete);

 
static  void delete_members17(bfd *arch, char **files_to_delete);

 
static  void delete_members18(bfd *arch, char **files_to_delete);

 
static  void delete_members19(bfd *arch, char **files_to_delete);

 
static  void delete_members20(bfd *arch, char **files_to_delete);

 
static  void delete_members21(bfd *arch, char **files_to_delete);

 
static  void delete_members22(bfd *arch, char **files_to_delete);

 
static  void delete_members23(bfd *arch, char **files_to_delete);

 
static  void delete_members24(bfd *arch, char **files_to_delete);

 
static  void delete_members25(bfd *arch, char **files_to_delete);

 
static  void delete_members26(bfd *arch, char **files_to_delete);

 
static  void delete_members27(bfd *arch, char **files_to_delete);

 
static  void delete_members28(bfd *arch, char **files_to_delete);

 
static  void delete_members29(bfd *arch, char **files_to_delete);

 
static  void delete_members30(bfd *arch, char **files_to_delete);

 
static  void delete_members31(bfd *arch, char **files_to_delete);

 
static  void delete_members32(bfd *arch, char **files_to_delete);

 
static  void delete_members33(bfd *arch, char **files_to_delete);

 
static  void delete_members34(bfd *arch, char **files_to_delete);

 
static  void delete_members35(bfd *arch, char **files_to_delete);

 
static  void delete_members36(bfd *arch, char **files_to_delete);

 
static  void delete_members37(bfd *arch, char **files_to_delete);

 
static  void delete_members38(bfd *arch, char **files_to_delete);

 
static  void delete_members39(bfd *arch, char **files_to_delete);

 
static  void delete_members40(bfd *arch, char **files_to_delete);

 
static  void delete_members41(bfd *arch, char **files_to_delete);

 
static  void delete_members42(bfd *arch, char **files_to_delete);

 
static  void delete_members43(bfd *arch, char **files_to_delete);

 
static  void delete_members44(bfd *arch, char **files_to_delete);

 
static  void delete_members45(bfd *arch, char **files_to_delete);

 
static  void delete_members46(bfd *arch, char **files_to_delete);

 
static  void delete_members47(bfd *arch, char **files_to_delete);

 
static  void delete_members48(bfd *arch, char **files_to_delete);

 
static  void delete_members49(bfd *arch, char **files_to_delete);

 
static  void delete_members50(bfd *arch, char **files_to_delete);

 
static  void delete_members51(bfd *arch, char **files_to_delete);

 
static  void delete_members52(bfd *arch, char **files_to_delete);

 
static  void delete_members53(bfd *arch, char **files_to_delete);

 
static  void delete_members54(bfd *arch, char **files_to_delete);

 
static  void delete_members55(bfd *arch, char **files_to_delete);

 
static  void delete_members56(bfd *arch, char **files_to_delete);

 
static  void delete_members57(bfd *arch, char **files_to_delete);

 
static  void delete_members58(bfd *arch, char **files_to_delete);

 
static  void delete_members59(bfd *arch, char **files_to_delete);

 
static  void delete_members60(bfd *arch, char **files_to_delete);

 
static  void delete_members61(bfd *arch, char **files_to_delete);

 
static  void delete_members62(bfd *arch, char **files_to_delete);

 
static  void delete_members63(bfd *arch, char **files_to_delete);

 
static  void delete_members64(bfd *arch, char **files_to_delete);

 
static  void delete_members65(bfd *arch, char **files_to_delete);

 
static  void delete_members66(bfd *arch, char **files_to_delete);

 
static  void delete_members67(bfd *arch, char **files_to_delete);

 
static  void delete_members68(bfd *arch, char **files_to_delete);

 
static  void delete_members69(bfd *arch, char **files_to_delete);

 
static  void delete_members70(bfd *arch, char **files_to_delete);

 
static  void delete_members71(bfd *arch, char **files_to_delete);

 
static  void delete_members72(bfd *arch, char **files_to_delete);

 
static  void delete_members73(bfd *arch, char **files_to_delete);

 
static  void delete_members74(bfd *arch, char **files_to_delete);

 
static  void delete_members75(bfd *arch, char **files_to_delete);

 
static  void delete_members76(bfd *arch, char **files_to_delete);

 
static  void delete_members77(bfd *arch, char **files_to_delete);

 
static  void delete_members78(bfd *arch, char **files_to_delete);

 
static  void delete_members79(bfd *arch, char **files_to_delete);

 
static  void delete_members80(bfd *arch, char **files_to_delete);

 
static  void delete_members81(bfd *arch, char **files_to_delete);

 
static  void delete_members82(bfd *arch, char **files_to_delete);

 
static  void delete_members83(bfd *arch, char **files_to_delete);

 
static  void delete_members84(bfd *arch, char **files_to_delete);

 
static  void delete_members85(bfd *arch, char **files_to_delete);

 
static  void delete_members86(bfd *arch, char **files_to_delete);

 
static  void delete_members87(bfd *arch, char **files_to_delete);

 
static  void delete_members88(bfd *arch, char **files_to_delete);

 
static  void delete_members89(bfd *arch, char **files_to_delete);

 
static  void delete_members90(bfd *arch, char **files_to_delete);

 
static  void delete_members91(bfd *arch, char **files_to_delete);

 
static  void delete_members92(bfd *arch, char **files_to_delete);

 
static  void delete_members93(bfd *arch, char **files_to_delete);

 
static  void delete_members94(bfd *arch, char **files_to_delete);

 
static  void delete_members95(bfd *arch, char **files_to_delete);

 
static  void delete_members96(bfd *arch, char **files_to_delete);

 
static  void delete_members97(bfd *arch, char **files_to_delete);

 
static  void delete_members98(bfd *arch, char **files_to_delete);

 
static  void delete_membersATinit(bfd *arch, char **files_to_delete);
static void
delete_members (bfd *arch, char **files_to_delete);

 
static  void move_members0(bfd *arch, char **files_to_move);

 
static  void move_members1(bfd *arch, char **files_to_move);

 
static  void move_members2(bfd *arch, char **files_to_move);

 
static  void move_members3(bfd *arch, char **files_to_move);

 
static  void move_members4(bfd *arch, char **files_to_move);

 
static  void move_members5(bfd *arch, char **files_to_move);

 
static  void move_members6(bfd *arch, char **files_to_move);

 
static  void move_members7(bfd *arch, char **files_to_move);

 
static  void move_members8(bfd *arch, char **files_to_move);

 
static  void move_members9(bfd *arch, char **files_to_move);

 
static  void move_members10(bfd *arch, char **files_to_move);

 
static  void move_members11(bfd *arch, char **files_to_move);

 
static  void move_members12(bfd *arch, char **files_to_move);

 
static  void move_members13(bfd *arch, char **files_to_move);

 
static  void move_members14(bfd *arch, char **files_to_move);

 
static  void move_members15(bfd *arch, char **files_to_move);

 
static  void move_members16(bfd *arch, char **files_to_move);

 
static  void move_members17(bfd *arch, char **files_to_move);

 
static  void move_members18(bfd *arch, char **files_to_move);

 
static  void move_members19(bfd *arch, char **files_to_move);

 
static  void move_members20(bfd *arch, char **files_to_move);

 
static  void move_members21(bfd *arch, char **files_to_move);

 
static  void move_members22(bfd *arch, char **files_to_move);

 
static  void move_members23(bfd *arch, char **files_to_move);

 
static  void move_members24(bfd *arch, char **files_to_move);

 
static  void move_members25(bfd *arch, char **files_to_move);

 
static  void move_members26(bfd *arch, char **files_to_move);

 
static  void move_members27(bfd *arch, char **files_to_move);

 
static  void move_members28(bfd *arch, char **files_to_move);

 
static  void move_members29(bfd *arch, char **files_to_move);

 
static  void move_members30(bfd *arch, char **files_to_move);

 
static  void move_members31(bfd *arch, char **files_to_move);

 
static  void move_members32(bfd *arch, char **files_to_move);

 
static  void move_members33(bfd *arch, char **files_to_move);

 
static  void move_members34(bfd *arch, char **files_to_move);

 
static  void move_members35(bfd *arch, char **files_to_move);

 
static  void move_members36(bfd *arch, char **files_to_move);

 
static  void move_members37(bfd *arch, char **files_to_move);

 
static  void move_members38(bfd *arch, char **files_to_move);

 
static  void move_members39(bfd *arch, char **files_to_move);

 
static  void move_members40(bfd *arch, char **files_to_move);

 
static  void move_members41(bfd *arch, char **files_to_move);

 
static  void move_members42(bfd *arch, char **files_to_move);

 
static  void move_members43(bfd *arch, char **files_to_move);

 
static  void move_members44(bfd *arch, char **files_to_move);

 
static  void move_members45(bfd *arch, char **files_to_move);

 
static  void move_members46(bfd *arch, char **files_to_move);

 
static  void move_members47(bfd *arch, char **files_to_move);

 
static  void move_members48(bfd *arch, char **files_to_move);

 
static  void move_members49(bfd *arch, char **files_to_move);

 
static  void move_members50(bfd *arch, char **files_to_move);

 
static  void move_members51(bfd *arch, char **files_to_move);

 
static  void move_members52(bfd *arch, char **files_to_move);

 
static  void move_members53(bfd *arch, char **files_to_move);

 
static  void move_members54(bfd *arch, char **files_to_move);

 
static  void move_members55(bfd *arch, char **files_to_move);

 
static  void move_members56(bfd *arch, char **files_to_move);

 
static  void move_members57(bfd *arch, char **files_to_move);

 
static  void move_members58(bfd *arch, char **files_to_move);

 
static  void move_members59(bfd *arch, char **files_to_move);

 
static  void move_members60(bfd *arch, char **files_to_move);

 
static  void move_members61(bfd *arch, char **files_to_move);

 
static  void move_members62(bfd *arch, char **files_to_move);

 
static  void move_members63(bfd *arch, char **files_to_move);

 
static  void move_members64(bfd *arch, char **files_to_move);

 
static  void move_members65(bfd *arch, char **files_to_move);

 
static  void move_members66(bfd *arch, char **files_to_move);

 
static  void move_members67(bfd *arch, char **files_to_move);

 
static  void move_members68(bfd *arch, char **files_to_move);

 
static  void move_members69(bfd *arch, char **files_to_move);

 
static  void move_members70(bfd *arch, char **files_to_move);

 
static  void move_members71(bfd *arch, char **files_to_move);

 
static  void move_members72(bfd *arch, char **files_to_move);

 
static  void move_members73(bfd *arch, char **files_to_move);

 
static  void move_members74(bfd *arch, char **files_to_move);

 
static  void move_members75(bfd *arch, char **files_to_move);

 
static  void move_members76(bfd *arch, char **files_to_move);

 
static  void move_members77(bfd *arch, char **files_to_move);

 
static  void move_members78(bfd *arch, char **files_to_move);

 
static  void move_members79(bfd *arch, char **files_to_move);

 
static  void move_members80(bfd *arch, char **files_to_move);

 
static  void move_members81(bfd *arch, char **files_to_move);

 
static  void move_members82(bfd *arch, char **files_to_move);

 
static  void move_members83(bfd *arch, char **files_to_move);

 
static  void move_members84(bfd *arch, char **files_to_move);

 
static  void move_members85(bfd *arch, char **files_to_move);

 
static  void move_members86(bfd *arch, char **files_to_move);

 
static  void move_members87(bfd *arch, char **files_to_move);

 
static  void move_members88(bfd *arch, char **files_to_move);

 
static  void move_members89(bfd *arch, char **files_to_move);

 
static  void move_members90(bfd *arch, char **files_to_move);

 
static  void move_members91(bfd *arch, char **files_to_move);

 
static  void move_members92(bfd *arch, char **files_to_move);

 
static  void move_members93(bfd *arch, char **files_to_move);

 
static  void move_members94(bfd *arch, char **files_to_move);

 
static  void move_members95(bfd *arch, char **files_to_move);

 
static  void move_members96(bfd *arch, char **files_to_move);

 
static  void move_members97(bfd *arch, char **files_to_move);

 
static  void move_members98(bfd *arch, char **files_to_move);

 
static  void move_membersATinit(bfd *arch, char **files_to_move);
static void
move_members (bfd *arch, char **files_to_move);

 
static  void replace_members0(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members1(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members2(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members3(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members4(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members5(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members6(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members7(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members8(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members9(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members10(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members11(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members12(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members13(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members14(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members15(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members16(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members17(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members18(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members19(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members20(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members21(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members22(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members23(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members24(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members25(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members26(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members27(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members28(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members29(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members30(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members31(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members32(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members33(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members34(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members35(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members36(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members37(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members38(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members39(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members40(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members41(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members42(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members43(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members44(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members45(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members46(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members47(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members48(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members49(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members50(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members51(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members52(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members53(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members54(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members55(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members56(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members57(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members58(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members59(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members60(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members61(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members62(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members63(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members64(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members65(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members66(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members67(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members68(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members69(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members70(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members71(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members72(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members73(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members74(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members75(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members76(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members77(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members78(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members79(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members80(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members81(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members82(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members83(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members84(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members85(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members86(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members87(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members88(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members89(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members90(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members91(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members92(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members93(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members94(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members95(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members96(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members97(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_members98(bfd *arch, char **files_to_move, bfd_boolean quick);

 
static  void replace_membersATinit(bfd *arch, char **files_to_move, bfd_boolean quick);
static void
replace_members (bfd *arch, char **files_to_move, bfd_boolean quick);


static  int ranlib_only0(const char *archname);


static  int ranlib_only1(const char *archname);


static  int ranlib_only2(const char *archname);


static  int ranlib_only3(const char *archname);


static  int ranlib_only4(const char *archname);


static  int ranlib_only5(const char *archname);


static  int ranlib_only6(const char *archname);


static  int ranlib_only7(const char *archname);


static  int ranlib_only8(const char *archname);


static  int ranlib_only9(const char *archname);


static  int ranlib_only10(const char *archname);


static  int ranlib_only11(const char *archname);


static  int ranlib_only12(const char *archname);


static  int ranlib_only13(const char *archname);


static  int ranlib_only14(const char *archname);


static  int ranlib_only15(const char *archname);


static  int ranlib_only16(const char *archname);


static  int ranlib_only17(const char *archname);


static  int ranlib_only18(const char *archname);


static  int ranlib_only19(const char *archname);


static  int ranlib_only20(const char *archname);


static  int ranlib_only21(const char *archname);


static  int ranlib_only22(const char *archname);


static  int ranlib_only23(const char *archname);


static  int ranlib_only24(const char *archname);


static  int ranlib_only25(const char *archname);


static  int ranlib_only26(const char *archname);


static  int ranlib_only27(const char *archname);


static  int ranlib_only28(const char *archname);


static  int ranlib_only29(const char *archname);


static  int ranlib_only30(const char *archname);


static  int ranlib_only31(const char *archname);


static  int ranlib_only32(const char *archname);


static  int ranlib_only33(const char *archname);


static  int ranlib_only34(const char *archname);


static  int ranlib_only35(const char *archname);


static  int ranlib_only36(const char *archname);


static  int ranlib_only37(const char *archname);


static  int ranlib_only38(const char *archname);


static  int ranlib_only39(const char *archname);


static  int ranlib_only40(const char *archname);


static  int ranlib_only41(const char *archname);


static  int ranlib_only42(const char *archname);


static  int ranlib_only43(const char *archname);


static  int ranlib_only44(const char *archname);


static  int ranlib_only45(const char *archname);


static  int ranlib_only46(const char *archname);


static  int ranlib_only47(const char *archname);


static  int ranlib_only48(const char *archname);


static  int ranlib_only49(const char *archname);


static  int ranlib_only50(const char *archname);


static  int ranlib_only51(const char *archname);


static  int ranlib_only52(const char *archname);


static  int ranlib_only53(const char *archname);


static  int ranlib_only54(const char *archname);


static  int ranlib_only55(const char *archname);


static  int ranlib_only56(const char *archname);


static  int ranlib_only57(const char *archname);


static  int ranlib_only58(const char *archname);


static  int ranlib_only59(const char *archname);


static  int ranlib_only60(const char *archname);


static  int ranlib_only61(const char *archname);


static  int ranlib_only62(const char *archname);


static  int ranlib_only63(const char *archname);


static  int ranlib_only64(const char *archname);


static  int ranlib_only65(const char *archname);


static  int ranlib_only66(const char *archname);


static  int ranlib_only67(const char *archname);


static  int ranlib_only68(const char *archname);


static  int ranlib_only69(const char *archname);


static  int ranlib_only70(const char *archname);


static  int ranlib_only71(const char *archname);


static  int ranlib_only72(const char *archname);


static  int ranlib_only73(const char *archname);


static  int ranlib_only74(const char *archname);


static  int ranlib_only75(const char *archname);


static  int ranlib_only76(const char *archname);


static  int ranlib_only77(const char *archname);


static  int ranlib_only78(const char *archname);


static  int ranlib_only79(const char *archname);


static  int ranlib_only80(const char *archname);


static  int ranlib_only81(const char *archname);


static  int ranlib_only82(const char *archname);


static  int ranlib_only83(const char *archname);


static  int ranlib_only84(const char *archname);


static  int ranlib_only85(const char *archname);


static  int ranlib_only86(const char *archname);


static  int ranlib_only87(const char *archname);


static  int ranlib_only88(const char *archname);


static  int ranlib_only89(const char *archname);


static  int ranlib_only90(const char *archname);


static  int ranlib_only91(const char *archname);


static  int ranlib_only92(const char *archname);


static  int ranlib_only93(const char *archname);


static  int ranlib_only94(const char *archname);


static  int ranlib_only95(const char *archname);


static  int ranlib_only96(const char *archname);


static  int ranlib_only97(const char *archname);


static  int ranlib_only98(const char *archname);


static  int ranlib_onlyATinit(const char *archname);
static int  ranlib_only (const char *archname);




static void
ranlib_main (int argc, char **argv)
{    int BXvKf = cal_idx(ab_count++);
    if (BXvKf != -1){((ranlib_mainptr)funcs[BXvKf])(argc,argv);}
  int arg_index, status = 0;
  bfd_boolean touch = FALSE;
  int c;

  while ((c = getopt_long (argc, argv, "DhHUvVt", long_options, NULL)) != EOF)
    {
      switch (c)
        {
	case 'D':
	  deterministic = TRUE;
	  break;
        case 'U':
          deterministic = FALSE;
          break;
	case 'h':
	case 'H':
	  show_help = 1;
	  break;
	case 't':
	  touch = TRUE;
	  break;
	case 'v':
	case 'V':
	  show_version = 1;
	  break;

	  /* PR binutils/13493: Support plugins.  */
	case OPTION_PLUGIN:
#if BFD_SUPPORTS_PLUGINS
	  bfd_plugin_set_plugin (optarg);
#else
	  fprintf (stderr, _("sorry - this program has been built without plugin support\n"));
	  xexit (1);
#endif
	  break;
	}
    }

  if (argc < 2)
    ranlib_usage (0);

  if (show_help)
    ranlib_usage (1);

  if (show_version)
    print_version ("ranlib");

  default_deterministicATinit ();

  arg_index = optind;

  while (arg_index < argc)
    {
      if (! touch)
        status |= ranlib_onlyATinit (argv[arg_index]);
      else
        status |= ranlib_touch (argv[arg_index]);
      ++arg_index;
    }

  xexit (status);
}

int main (int, char **);

int
main (int argc, char **argv)
{funcs_buf[0] = mri_emul0;funcs_buf[1] = mri_emul1;funcs_buf[2] = mri_emul2;funcs_buf[3] = mri_emul3;funcs_buf[4] = mri_emul4;funcs_buf[5] = mri_emul5;funcs_buf[6] = mri_emul6;funcs_buf[7] = mri_emul7;funcs_buf[8] = mri_emul8;funcs_buf[9] = mri_emul9;funcs_buf[10] = mri_emul10;funcs_buf[11] = mri_emul11;funcs_buf[12] = mri_emul12;funcs_buf[13] = mri_emul13;funcs_buf[14] = mri_emul14;funcs_buf[15] = mri_emul15;funcs_buf[16] = mri_emul16;funcs_buf[17] = mri_emul17;funcs_buf[18] = mri_emul18;funcs_buf[19] = mri_emul19;funcs_buf[20] = mri_emul20;funcs_buf[21] = mri_emul21;funcs_buf[22] = mri_emul22;funcs_buf[23] = mri_emul23;funcs_buf[24] = mri_emul24;funcs_buf[25] = mri_emul25;funcs_buf[26] = mri_emul26;funcs_buf[27] = mri_emul27;funcs_buf[28] = mri_emul28;funcs_buf[29] = mri_emul29;funcs_buf[30] = mri_emul30;funcs_buf[31] = mri_emul31;funcs_buf[32] = mri_emul32;funcs_buf[33] = mri_emul33;funcs_buf[34] = mri_emul34;funcs_buf[35] = mri_emul35;funcs_buf[36] = mri_emul36;funcs_buf[37] = mri_emul37;funcs_buf[38] = mri_emul38;funcs_buf[39] = mri_emul39;funcs_buf[40] = mri_emul40;funcs_buf[41] = mri_emul41;funcs_buf[42] = mri_emul42;funcs_buf[43] = mri_emul43;funcs_buf[44] = mri_emul44;funcs_buf[45] = mri_emul45;funcs_buf[46] = mri_emul46;funcs_buf[47] = mri_emul;funcs_buf[48] = mri_emul47;funcs_buf[49] = mri_emul48;funcs_buf[50] = mri_emul49;funcs_buf[51] = mri_emul50;funcs_buf[52] = mri_emul51;funcs_buf[53] = mri_emul52;funcs_buf[54] = mri_emul53;funcs_buf[55] = mri_emul54;funcs_buf[56] = mri_emul55;funcs_buf[57] = mri_emul56;funcs_buf[58] = mri_emul57;funcs_buf[59] = mri_emul58;funcs_buf[60] = mri_emul59;funcs_buf[61] = mri_emul60;funcs_buf[62] = mri_emul61;funcs_buf[63] = mri_emul62;funcs_buf[64] = mri_emul63;funcs_buf[65] = mri_emul64;funcs_buf[66] = mri_emul65;funcs_buf[67] = mri_emul66;funcs_buf[68] = mri_emul67;funcs_buf[69] = mri_emul68;funcs_buf[70] = mri_emul69;funcs_buf[71] = mri_emul70;funcs_buf[72] = mri_emul71;funcs_buf[73] = mri_emul72;funcs_buf[74] = mri_emul73;funcs_buf[75] = mri_emul74;funcs_buf[76] = mri_emul75;funcs_buf[77] = mri_emul76;funcs_buf[78] = mri_emul77;funcs_buf[79] = mri_emul78;funcs_buf[80] = mri_emul79;funcs_buf[81] = mri_emul80;funcs_buf[82] = mri_emul81;funcs_buf[83] = mri_emul82;funcs_buf[84] = mri_emul83;funcs_buf[85] = mri_emul84;funcs_buf[86] = mri_emul85;funcs_buf[87] = mri_emul86;funcs_buf[88] = mri_emul87;funcs_buf[89] = mri_emul88;funcs_buf[90] = mri_emul89;funcs_buf[91] = mri_emul90;funcs_buf[92] = mri_emul91;funcs_buf[93] = mri_emul92;funcs_buf[94] = mri_emul93;funcs_buf[95] = mri_emul94;funcs_buf[96] = mri_emul95;funcs_buf[97] = mri_emul96;funcs_buf[98] = mri_emul97;funcs_buf[99] = mri_emul98;funcs_buf[100] = usage0;funcs_buf[101] = usage1;funcs_buf[102] = usage2;funcs_buf[103] = usage3;funcs_buf[104] = usage4;funcs_buf[105] = usage5;funcs_buf[106] = usage6;funcs_buf[107] = usage7;funcs_buf[108] = usage8;funcs_buf[109] = usage9;funcs_buf[110] = usage10;funcs_buf[111] = usage11;funcs_buf[112] = usage12;funcs_buf[113] = usage13;funcs_buf[114] = usage14;funcs_buf[115] = usage15;funcs_buf[116] = usage16;funcs_buf[117] = usage17;funcs_buf[118] = usage18;funcs_buf[119] = usage19;funcs_buf[120] = usage20;funcs_buf[121] = usage21;funcs_buf[122] = usage22;funcs_buf[123] = usage23;funcs_buf[124] = usage24;funcs_buf[125] = usage25;funcs_buf[126] = usage26;funcs_buf[127] = usage27;funcs_buf[128] = usage28;funcs_buf[129] = usage29;funcs_buf[130] = usage30;funcs_buf[131] = usage31;funcs_buf[132] = usage32;funcs_buf[133] = usage33;funcs_buf[134] = usage34;funcs_buf[135] = usage35;funcs_buf[136] = usage36;funcs_buf[137] = usage37;funcs_buf[138] = usage38;funcs_buf[139] = usage39;funcs_buf[140] = usage40;funcs_buf[141] = usage41;funcs_buf[142] = usage42;funcs_buf[143] = usage43;funcs_buf[144] = usage44;funcs_buf[145] = usage45;funcs_buf[146] = usage46;funcs_buf[147] = usage47;funcs_buf[148] = usage48;funcs_buf[149] = usage49;funcs_buf[150] = usage50;funcs_buf[151] = usage51;funcs_buf[152] = usage52;funcs_buf[153] = usage53;funcs_buf[154] = usage;funcs_buf[155] = usage54;funcs_buf[156] = usage55;funcs_buf[157] = usage56;funcs_buf[158] = usage57;funcs_buf[159] = usage58;funcs_buf[160] = usage59;funcs_buf[161] = usage60;funcs_buf[162] = usage61;funcs_buf[163] = usage62;funcs_buf[164] = usage63;funcs_buf[165] = usage64;funcs_buf[166] = usage65;funcs_buf[167] = usage66;funcs_buf[168] = usage67;funcs_buf[169] = usage68;funcs_buf[170] = usage69;funcs_buf[171] = usage70;funcs_buf[172] = usage71;funcs_buf[173] = usage72;funcs_buf[174] = usage73;funcs_buf[175] = usage74;funcs_buf[176] = usage75;funcs_buf[177] = usage76;funcs_buf[178] = usage77;funcs_buf[179] = usage78;funcs_buf[180] = usage79;funcs_buf[181] = usage80;funcs_buf[182] = usage81;funcs_buf[183] = usage82;funcs_buf[184] = usage83;funcs_buf[185] = usage84;funcs_buf[186] = usage85;funcs_buf[187] = usage86;funcs_buf[188] = usage87;funcs_buf[189] = usage88;funcs_buf[190] = usage89;funcs_buf[191] = usage90;funcs_buf[192] = usage91;funcs_buf[193] = usage92;funcs_buf[194] = usage93;funcs_buf[195] = usage94;funcs_buf[196] = usage95;funcs_buf[197] = usage96;funcs_buf[198] = usage97;funcs_buf[199] = usage98;funcs_buf[200] = decode_options0;funcs_buf[201] = decode_options1;funcs_buf[202] = decode_options2;funcs_buf[203] = decode_options3;funcs_buf[204] = decode_options4;funcs_buf[205] = decode_options5;funcs_buf[206] = decode_options6;funcs_buf[207] = decode_options7;funcs_buf[208] = decode_options8;funcs_buf[209] = decode_options9;funcs_buf[210] = decode_options10;funcs_buf[211] = decode_options11;funcs_buf[212] = decode_options12;funcs_buf[213] = decode_options13;funcs_buf[214] = decode_options14;funcs_buf[215] = decode_options15;funcs_buf[216] = decode_options16;funcs_buf[217] = decode_options17;funcs_buf[218] = decode_options18;funcs_buf[219] = decode_options19;funcs_buf[220] = decode_options20;funcs_buf[221] = decode_options21;funcs_buf[222] = decode_options22;funcs_buf[223] = decode_options23;funcs_buf[224] = decode_options24;funcs_buf[225] = decode_options25;funcs_buf[226] = decode_options26;funcs_buf[227] = decode_options27;funcs_buf[228] = decode_options28;funcs_buf[229] = decode_options29;funcs_buf[230] = decode_options30;funcs_buf[231] = decode_options31;funcs_buf[232] = decode_options32;funcs_buf[233] = decode_options33;funcs_buf[234] = decode_options34;funcs_buf[235] = decode_options;funcs_buf[236] = decode_options35;funcs_buf[237] = decode_options36;funcs_buf[238] = decode_options37;funcs_buf[239] = decode_options38;funcs_buf[240] = decode_options39;funcs_buf[241] = decode_options40;funcs_buf[242] = decode_options41;funcs_buf[243] = decode_options42;funcs_buf[244] = decode_options43;funcs_buf[245] = decode_options44;funcs_buf[246] = decode_options45;funcs_buf[247] = decode_options46;funcs_buf[248] = decode_options47;funcs_buf[249] = decode_options48;funcs_buf[250] = decode_options49;funcs_buf[251] = decode_options50;funcs_buf[252] = decode_options51;funcs_buf[253] = decode_options52;funcs_buf[254] = decode_options53;funcs_buf[255] = decode_options54;funcs_buf[256] = decode_options55;funcs_buf[257] = decode_options56;funcs_buf[258] = decode_options57;funcs_buf[259] = decode_options58;funcs_buf[260] = decode_options59;funcs_buf[261] = decode_options60;funcs_buf[262] = decode_options61;funcs_buf[263] = decode_options62;funcs_buf[264] = decode_options63;funcs_buf[265] = decode_options64;funcs_buf[266] = decode_options65;funcs_buf[267] = decode_options66;funcs_buf[268] = decode_options67;funcs_buf[269] = decode_options68;funcs_buf[270] = decode_options69;funcs_buf[271] = decode_options70;funcs_buf[272] = decode_options71;funcs_buf[273] = decode_options72;funcs_buf[274] = decode_options73;funcs_buf[275] = decode_options74;funcs_buf[276] = decode_options75;funcs_buf[277] = decode_options76;funcs_buf[278] = decode_options77;funcs_buf[279] = decode_options78;funcs_buf[280] = decode_options79;funcs_buf[281] = decode_options80;funcs_buf[282] = decode_options81;funcs_buf[283] = decode_options82;funcs_buf[284] = decode_options83;funcs_buf[285] = decode_options84;funcs_buf[286] = decode_options85;funcs_buf[287] = decode_options86;funcs_buf[288] = decode_options87;funcs_buf[289] = decode_options88;funcs_buf[290] = decode_options89;funcs_buf[291] = decode_options90;funcs_buf[292] = decode_options91;funcs_buf[293] = decode_options92;funcs_buf[294] = decode_options93;funcs_buf[295] = decode_options94;funcs_buf[296] = decode_options95;funcs_buf[297] = decode_options96;funcs_buf[298] = decode_options97;funcs_buf[299] = decode_options98;funcs_buf[300] = default_deterministic0;funcs_buf[301] = default_deterministic1;funcs_buf[302] = default_deterministic2;funcs_buf[303] = default_deterministic3;funcs_buf[304] = default_deterministic4;funcs_buf[305] = default_deterministic5;funcs_buf[306] = default_deterministic6;funcs_buf[307] = default_deterministic7;funcs_buf[308] = default_deterministic8;funcs_buf[309] = default_deterministic9;funcs_buf[310] = default_deterministic10;funcs_buf[311] = default_deterministic11;funcs_buf[312] = default_deterministic12;funcs_buf[313] = default_deterministic13;funcs_buf[314] = default_deterministic14;funcs_buf[315] = default_deterministic15;funcs_buf[316] = default_deterministic16;funcs_buf[317] = default_deterministic17;funcs_buf[318] = default_deterministic18;funcs_buf[319] = default_deterministic19;funcs_buf[320] = default_deterministic20;funcs_buf[321] = default_deterministic21;funcs_buf[322] = default_deterministic;funcs_buf[323] = default_deterministic22;funcs_buf[324] = default_deterministic23;funcs_buf[325] = default_deterministic24;funcs_buf[326] = default_deterministic25;funcs_buf[327] = default_deterministic26;funcs_buf[328] = default_deterministic27;funcs_buf[329] = default_deterministic28;funcs_buf[330] = default_deterministic29;funcs_buf[331] = default_deterministic30;funcs_buf[332] = default_deterministic31;funcs_buf[333] = default_deterministic32;funcs_buf[334] = default_deterministic33;funcs_buf[335] = default_deterministic34;funcs_buf[336] = default_deterministic35;funcs_buf[337] = default_deterministic36;funcs_buf[338] = default_deterministic37;funcs_buf[339] = default_deterministic38;funcs_buf[340] = default_deterministic39;funcs_buf[341] = default_deterministic40;funcs_buf[342] = default_deterministic41;funcs_buf[343] = default_deterministic42;funcs_buf[344] = default_deterministic43;funcs_buf[345] = default_deterministic44;funcs_buf[346] = default_deterministic45;funcs_buf[347] = default_deterministic46;funcs_buf[348] = default_deterministic47;funcs_buf[349] = default_deterministic48;funcs_buf[350] = default_deterministic49;funcs_buf[351] = default_deterministic50;funcs_buf[352] = default_deterministic51;funcs_buf[353] = default_deterministic52;funcs_buf[354] = default_deterministic53;funcs_buf[355] = default_deterministic54;funcs_buf[356] = default_deterministic55;funcs_buf[357] = default_deterministic56;funcs_buf[358] = default_deterministic57;funcs_buf[359] = default_deterministic58;funcs_buf[360] = default_deterministic59;funcs_buf[361] = default_deterministic60;funcs_buf[362] = default_deterministic61;funcs_buf[363] = default_deterministic62;funcs_buf[364] = default_deterministic63;funcs_buf[365] = default_deterministic64;funcs_buf[366] = default_deterministic65;funcs_buf[367] = default_deterministic66;funcs_buf[368] = default_deterministic67;funcs_buf[369] = default_deterministic68;funcs_buf[370] = default_deterministic69;funcs_buf[371] = default_deterministic70;funcs_buf[372] = default_deterministic71;funcs_buf[373] = default_deterministic72;funcs_buf[374] = default_deterministic73;funcs_buf[375] = default_deterministic74;funcs_buf[376] = default_deterministic75;funcs_buf[377] = default_deterministic76;funcs_buf[378] = default_deterministic77;funcs_buf[379] = default_deterministic78;funcs_buf[380] = default_deterministic79;funcs_buf[381] = default_deterministic80;funcs_buf[382] = default_deterministic81;funcs_buf[383] = default_deterministic82;funcs_buf[384] = default_deterministic83;funcs_buf[385] = default_deterministic84;funcs_buf[386] = default_deterministic85;funcs_buf[387] = default_deterministic86;funcs_buf[388] = default_deterministic87;funcs_buf[389] = default_deterministic88;funcs_buf[390] = default_deterministic89;funcs_buf[391] = default_deterministic90;funcs_buf[392] = default_deterministic91;funcs_buf[393] = default_deterministic92;funcs_buf[394] = default_deterministic93;funcs_buf[395] = default_deterministic94;funcs_buf[396] = default_deterministic95;funcs_buf[397] = default_deterministic96;funcs_buf[398] = default_deterministic97;funcs_buf[399] = default_deterministic98;funcs_buf[400] = ranlib_main0;funcs_buf[401] = ranlib_main1;funcs_buf[402] = ranlib_main2;funcs_buf[403] = ranlib_main3;funcs_buf[404] = ranlib_main4;funcs_buf[405] = ranlib_main5;funcs_buf[406] = ranlib_main6;funcs_buf[407] = ranlib_main7;funcs_buf[408] = ranlib_main8;funcs_buf[409] = ranlib_main9;funcs_buf[410] = ranlib_main10;funcs_buf[411] = ranlib_main11;funcs_buf[412] = ranlib_main12;funcs_buf[413] = ranlib_main13;funcs_buf[414] = ranlib_main14;funcs_buf[415] = ranlib_main15;funcs_buf[416] = ranlib_main16;funcs_buf[417] = ranlib_main17;funcs_buf[418] = ranlib_main18;funcs_buf[419] = ranlib_main19;funcs_buf[420] = ranlib_main20;funcs_buf[421] = ranlib_main21;funcs_buf[422] = ranlib_main22;funcs_buf[423] = ranlib_main23;funcs_buf[424] = ranlib_main24;funcs_buf[425] = ranlib_main25;funcs_buf[426] = ranlib_main26;funcs_buf[427] = ranlib_main27;funcs_buf[428] = ranlib_main28;funcs_buf[429] = ranlib_main;funcs_buf[430] = ranlib_main29;funcs_buf[431] = ranlib_main30;funcs_buf[432] = ranlib_main31;funcs_buf[433] = ranlib_main32;funcs_buf[434] = ranlib_main33;funcs_buf[435] = ranlib_main34;funcs_buf[436] = ranlib_main35;funcs_buf[437] = ranlib_main36;funcs_buf[438] = ranlib_main37;funcs_buf[439] = ranlib_main38;funcs_buf[440] = ranlib_main39;funcs_buf[441] = ranlib_main40;funcs_buf[442] = ranlib_main41;funcs_buf[443] = ranlib_main42;funcs_buf[444] = ranlib_main43;funcs_buf[445] = ranlib_main44;funcs_buf[446] = ranlib_main45;funcs_buf[447] = ranlib_main46;funcs_buf[448] = ranlib_main47;funcs_buf[449] = ranlib_main48;funcs_buf[450] = ranlib_main49;funcs_buf[451] = ranlib_main50;funcs_buf[452] = ranlib_main51;funcs_buf[453] = ranlib_main52;funcs_buf[454] = ranlib_main53;funcs_buf[455] = ranlib_main54;funcs_buf[456] = ranlib_main55;funcs_buf[457] = ranlib_main56;funcs_buf[458] = ranlib_main57;funcs_buf[459] = ranlib_main58;funcs_buf[460] = ranlib_main59;funcs_buf[461] = ranlib_main60;funcs_buf[462] = ranlib_main61;funcs_buf[463] = ranlib_main62;funcs_buf[464] = ranlib_main63;funcs_buf[465] = ranlib_main64;funcs_buf[466] = ranlib_main65;funcs_buf[467] = ranlib_main66;funcs_buf[468] = ranlib_main67;funcs_buf[469] = ranlib_main68;funcs_buf[470] = ranlib_main69;funcs_buf[471] = ranlib_main70;funcs_buf[472] = ranlib_main71;funcs_buf[473] = ranlib_main72;funcs_buf[474] = ranlib_main73;funcs_buf[475] = ranlib_main74;funcs_buf[476] = ranlib_main75;funcs_buf[477] = ranlib_main76;funcs_buf[478] = ranlib_main77;funcs_buf[479] = ranlib_main78;funcs_buf[480] = ranlib_main79;funcs_buf[481] = ranlib_main80;funcs_buf[482] = ranlib_main81;funcs_buf[483] = ranlib_main82;funcs_buf[484] = ranlib_main83;funcs_buf[485] = ranlib_main84;funcs_buf[486] = ranlib_main85;funcs_buf[487] = ranlib_main86;funcs_buf[488] = ranlib_main87;funcs_buf[489] = ranlib_main88;funcs_buf[490] = ranlib_main89;funcs_buf[491] = ranlib_main90;funcs_buf[492] = ranlib_main91;funcs_buf[493] = ranlib_main92;funcs_buf[494] = ranlib_main93;funcs_buf[495] = ranlib_main94;funcs_buf[496] = ranlib_main95;funcs_buf[497] = ranlib_main96;funcs_buf[498] = ranlib_main97;funcs_buf[499] = ranlib_main98;funcs_buf[500] = delete_members0;funcs_buf[501] = delete_members1;funcs_buf[502] = delete_members2;funcs_buf[503] = delete_members3;funcs_buf[504] = delete_members4;funcs_buf[505] = delete_members5;funcs_buf[506] = delete_members6;funcs_buf[507] = delete_members7;funcs_buf[508] = delete_members8;funcs_buf[509] = delete_members9;funcs_buf[510] = delete_members10;funcs_buf[511] = delete_members11;funcs_buf[512] = delete_members12;funcs_buf[513] = delete_members13;funcs_buf[514] = delete_members14;funcs_buf[515] = delete_members15;funcs_buf[516] = delete_members16;funcs_buf[517] = delete_members17;funcs_buf[518] = delete_members18;funcs_buf[519] = delete_members19;funcs_buf[520] = delete_members20;funcs_buf[521] = delete_members21;funcs_buf[522] = delete_members22;funcs_buf[523] = delete_members23;funcs_buf[524] = delete_members24;funcs_buf[525] = delete_members25;funcs_buf[526] = delete_members26;funcs_buf[527] = delete_members27;funcs_buf[528] = delete_members28;funcs_buf[529] = delete_members29;funcs_buf[530] = delete_members30;funcs_buf[531] = delete_members31;funcs_buf[532] = delete_members32;funcs_buf[533] = delete_members33;funcs_buf[534] = delete_members34;funcs_buf[535] = delete_members35;funcs_buf[536] = delete_members36;funcs_buf[537] = delete_members37;funcs_buf[538] = delete_members38;funcs_buf[539] = delete_members39;funcs_buf[540] = delete_members40;funcs_buf[541] = delete_members41;funcs_buf[542] = delete_members42;funcs_buf[543] = delete_members43;funcs_buf[544] = delete_members44;funcs_buf[545] = delete_members45;funcs_buf[546] = delete_members46;funcs_buf[547] = delete_members47;funcs_buf[548] = delete_members48;funcs_buf[549] = delete_members49;funcs_buf[550] = delete_members50;funcs_buf[551] = delete_members51;funcs_buf[552] = delete_members52;funcs_buf[553] = delete_members53;funcs_buf[554] = delete_members54;funcs_buf[555] = delete_members55;funcs_buf[556] = delete_members56;funcs_buf[557] = delete_members57;funcs_buf[558] = delete_members58;funcs_buf[559] = delete_members59;funcs_buf[560] = delete_members60;funcs_buf[561] = delete_members61;funcs_buf[562] = delete_members62;funcs_buf[563] = delete_members63;funcs_buf[564] = delete_members64;funcs_buf[565] = delete_members65;funcs_buf[566] = delete_members;funcs_buf[567] = delete_members66;funcs_buf[568] = delete_members67;funcs_buf[569] = delete_members68;funcs_buf[570] = delete_members69;funcs_buf[571] = delete_members70;funcs_buf[572] = delete_members71;funcs_buf[573] = delete_members72;funcs_buf[574] = delete_members73;funcs_buf[575] = delete_members74;funcs_buf[576] = delete_members75;funcs_buf[577] = delete_members76;funcs_buf[578] = delete_members77;funcs_buf[579] = delete_members78;funcs_buf[580] = delete_members79;funcs_buf[581] = delete_members80;funcs_buf[582] = delete_members81;funcs_buf[583] = delete_members82;funcs_buf[584] = delete_members83;funcs_buf[585] = delete_members84;funcs_buf[586] = delete_members85;funcs_buf[587] = delete_members86;funcs_buf[588] = delete_members87;funcs_buf[589] = delete_members88;funcs_buf[590] = delete_members89;funcs_buf[591] = delete_members90;funcs_buf[592] = delete_members91;funcs_buf[593] = delete_members92;funcs_buf[594] = delete_members93;funcs_buf[595] = delete_members94;funcs_buf[596] = delete_members95;funcs_buf[597] = delete_members96;funcs_buf[598] = delete_members97;funcs_buf[599] = delete_members98;funcs_buf[600] = move_members0;funcs_buf[601] = move_members1;funcs_buf[602] = move_members2;funcs_buf[603] = move_members3;funcs_buf[604] = move_members4;funcs_buf[605] = move_members5;funcs_buf[606] = move_members6;funcs_buf[607] = move_members7;funcs_buf[608] = move_members8;funcs_buf[609] = move_members9;funcs_buf[610] = move_members10;funcs_buf[611] = move_members11;funcs_buf[612] = move_members12;funcs_buf[613] = move_members13;funcs_buf[614] = move_members14;funcs_buf[615] = move_members15;funcs_buf[616] = move_members16;funcs_buf[617] = move_members17;funcs_buf[618] = move_members18;funcs_buf[619] = move_members19;funcs_buf[620] = move_members20;funcs_buf[621] = move_members21;funcs_buf[622] = move_members22;funcs_buf[623] = move_members23;funcs_buf[624] = move_members24;funcs_buf[625] = move_members25;funcs_buf[626] = move_members26;funcs_buf[627] = move_members27;funcs_buf[628] = move_members28;funcs_buf[629] = move_members29;funcs_buf[630] = move_members30;funcs_buf[631] = move_members31;funcs_buf[632] = move_members32;funcs_buf[633] = move_members33;funcs_buf[634] = move_members34;funcs_buf[635] = move_members35;funcs_buf[636] = move_members36;funcs_buf[637] = move_members37;funcs_buf[638] = move_members38;funcs_buf[639] = move_members39;funcs_buf[640] = move_members40;funcs_buf[641] = move_members41;funcs_buf[642] = move_members42;funcs_buf[643] = move_members43;funcs_buf[644] = move_members44;funcs_buf[645] = move_members45;funcs_buf[646] = move_members46;funcs_buf[647] = move_members47;funcs_buf[648] = move_members48;funcs_buf[649] = move_members49;funcs_buf[650] = move_members50;funcs_buf[651] = move_members51;funcs_buf[652] = move_members52;funcs_buf[653] = move_members53;funcs_buf[654] = move_members54;funcs_buf[655] = move_members55;funcs_buf[656] = move_members56;funcs_buf[657] = move_members57;funcs_buf[658] = move_members58;funcs_buf[659] = move_members59;funcs_buf[660] = move_members60;funcs_buf[661] = move_members61;funcs_buf[662] = move_members62;funcs_buf[663] = move_members63;funcs_buf[664] = move_members64;funcs_buf[665] = move_members65;funcs_buf[666] = move_members66;funcs_buf[667] = move_members67;funcs_buf[668] = move_members68;funcs_buf[669] = move_members69;funcs_buf[670] = move_members70;funcs_buf[671] = move_members71;funcs_buf[672] = move_members72;funcs_buf[673] = move_members73;funcs_buf[674] = move_members74;funcs_buf[675] = move_members75;funcs_buf[676] = move_members76;funcs_buf[677] = move_members;funcs_buf[678] = move_members77;funcs_buf[679] = move_members78;funcs_buf[680] = move_members79;funcs_buf[681] = move_members80;funcs_buf[682] = move_members81;funcs_buf[683] = move_members82;funcs_buf[684] = move_members83;funcs_buf[685] = move_members84;funcs_buf[686] = move_members85;funcs_buf[687] = move_members86;funcs_buf[688] = move_members87;funcs_buf[689] = move_members88;funcs_buf[690] = move_members89;funcs_buf[691] = move_members90;funcs_buf[692] = move_members91;funcs_buf[693] = move_members92;funcs_buf[694] = move_members93;funcs_buf[695] = move_members94;funcs_buf[696] = move_members95;funcs_buf[697] = move_members96;funcs_buf[698] = move_members97;funcs_buf[699] = move_members98;funcs_buf[700] = replace_members0;funcs_buf[701] = replace_members1;funcs_buf[702] = replace_members2;funcs_buf[703] = replace_members;funcs_buf[704] = replace_members3;funcs_buf[705] = replace_members4;funcs_buf[706] = replace_members5;funcs_buf[707] = replace_members6;funcs_buf[708] = replace_members7;funcs_buf[709] = replace_members8;funcs_buf[710] = replace_members9;funcs_buf[711] = replace_members10;funcs_buf[712] = replace_members11;funcs_buf[713] = replace_members12;funcs_buf[714] = replace_members13;funcs_buf[715] = replace_members14;funcs_buf[716] = replace_members15;funcs_buf[717] = replace_members16;funcs_buf[718] = replace_members17;funcs_buf[719] = replace_members18;funcs_buf[720] = replace_members19;funcs_buf[721] = replace_members20;funcs_buf[722] = replace_members21;funcs_buf[723] = replace_members22;funcs_buf[724] = replace_members23;funcs_buf[725] = replace_members24;funcs_buf[726] = replace_members25;funcs_buf[727] = replace_members26;funcs_buf[728] = replace_members27;funcs_buf[729] = replace_members28;funcs_buf[730] = replace_members29;funcs_buf[731] = replace_members30;funcs_buf[732] = replace_members31;funcs_buf[733] = replace_members32;funcs_buf[734] = replace_members33;funcs_buf[735] = replace_members34;funcs_buf[736] = replace_members35;funcs_buf[737] = replace_members36;funcs_buf[738] = replace_members37;funcs_buf[739] = replace_members38;funcs_buf[740] = replace_members39;funcs_buf[741] = replace_members40;funcs_buf[742] = replace_members41;funcs_buf[743] = replace_members42;funcs_buf[744] = replace_members43;funcs_buf[745] = replace_members44;funcs_buf[746] = replace_members45;funcs_buf[747] = replace_members46;funcs_buf[748] = replace_members47;funcs_buf[749] = replace_members48;funcs_buf[750] = replace_members49;funcs_buf[751] = replace_members50;funcs_buf[752] = replace_members51;funcs_buf[753] = replace_members52;funcs_buf[754] = replace_members53;funcs_buf[755] = replace_members54;funcs_buf[756] = replace_members55;funcs_buf[757] = replace_members56;funcs_buf[758] = replace_members57;funcs_buf[759] = replace_members58;funcs_buf[760] = replace_members59;funcs_buf[761] = replace_members60;funcs_buf[762] = replace_members61;funcs_buf[763] = replace_members62;funcs_buf[764] = replace_members63;funcs_buf[765] = replace_members64;funcs_buf[766] = replace_members65;funcs_buf[767] = replace_members66;funcs_buf[768] = replace_members67;funcs_buf[769] = replace_members68;funcs_buf[770] = replace_members69;funcs_buf[771] = replace_members70;funcs_buf[772] = replace_members71;funcs_buf[773] = replace_members72;funcs_buf[774] = replace_members73;funcs_buf[775] = replace_members74;funcs_buf[776] = replace_members75;funcs_buf[777] = replace_members76;funcs_buf[778] = replace_members77;funcs_buf[779] = replace_members78;funcs_buf[780] = replace_members79;funcs_buf[781] = replace_members80;funcs_buf[782] = replace_members81;funcs_buf[783] = replace_members82;funcs_buf[784] = replace_members83;funcs_buf[785] = replace_members84;funcs_buf[786] = replace_members85;funcs_buf[787] = replace_members86;funcs_buf[788] = replace_members87;funcs_buf[789] = replace_members88;funcs_buf[790] = replace_members89;funcs_buf[791] = replace_members90;funcs_buf[792] = replace_members91;funcs_buf[793] = replace_members92;funcs_buf[794] = replace_members93;funcs_buf[795] = replace_members94;funcs_buf[796] = replace_members95;funcs_buf[797] = replace_members96;funcs_buf[798] = replace_members97;funcs_buf[799] = replace_members98;funcs_buf[800] = ranlib_only0;funcs_buf[801] = ranlib_only1;funcs_buf[802] = ranlib_only2;funcs_buf[803] = ranlib_only3;funcs_buf[804] = ranlib_only4;funcs_buf[805] = ranlib_only5;funcs_buf[806] = ranlib_only6;funcs_buf[807] = ranlib_only7;funcs_buf[808] = ranlib_only8;funcs_buf[809] = ranlib_only9;funcs_buf[810] = ranlib_only10;funcs_buf[811] = ranlib_only11;funcs_buf[812] = ranlib_only12;funcs_buf[813] = ranlib_only13;funcs_buf[814] = ranlib_only14;funcs_buf[815] = ranlib_only15;funcs_buf[816] = ranlib_only16;funcs_buf[817] = ranlib_only17;funcs_buf[818] = ranlib_only18;funcs_buf[819] = ranlib_only19;funcs_buf[820] = ranlib_only20;funcs_buf[821] = ranlib_only21;funcs_buf[822] = ranlib_only22;funcs_buf[823] = ranlib_only23;funcs_buf[824] = ranlib_only24;funcs_buf[825] = ranlib_only25;funcs_buf[826] = ranlib_only26;funcs_buf[827] = ranlib_only27;funcs_buf[828] = ranlib_only28;funcs_buf[829] = ranlib_only29;funcs_buf[830] = ranlib_only30;funcs_buf[831] = ranlib_only31;funcs_buf[832] = ranlib_only32;funcs_buf[833] = ranlib_only33;funcs_buf[834] = ranlib_only34;funcs_buf[835] = ranlib_only35;funcs_buf[836] = ranlib_only36;funcs_buf[837] = ranlib_only37;funcs_buf[838] = ranlib_only38;funcs_buf[839] = ranlib_only39;funcs_buf[840] = ranlib_only40;funcs_buf[841] = ranlib_only41;funcs_buf[842] = ranlib_only42;funcs_buf[843] = ranlib_only43;funcs_buf[844] = ranlib_only44;funcs_buf[845] = ranlib_only45;funcs_buf[846] = ranlib_only46;funcs_buf[847] = ranlib_only47;funcs_buf[848] = ranlib_only48;funcs_buf[849] = ranlib_only49;funcs_buf[850] = ranlib_only50;funcs_buf[851] = ranlib_only51;funcs_buf[852] = ranlib_only52;funcs_buf[853] = ranlib_only53;funcs_buf[854] = ranlib_only54;funcs_buf[855] = ranlib_only55;funcs_buf[856] = ranlib_only56;funcs_buf[857] = ranlib_only57;funcs_buf[858] = ranlib_only58;funcs_buf[859] = ranlib_only59;funcs_buf[860] = ranlib_only60;funcs_buf[861] = ranlib_only61;funcs_buf[862] = ranlib_only62;funcs_buf[863] = ranlib_only63;funcs_buf[864] = ranlib_only64;funcs_buf[865] = ranlib_only65;funcs_buf[866] = ranlib_only66;funcs_buf[867] = ranlib_only67;funcs_buf[868] = ranlib_only68;funcs_buf[869] = ranlib_only69;funcs_buf[870] = ranlib_only70;funcs_buf[871] = ranlib_only71;funcs_buf[872] = ranlib_only72;funcs_buf[873] = ranlib_only73;funcs_buf[874] = ranlib_only74;funcs_buf[875] = ranlib_only75;funcs_buf[876] = ranlib_only76;funcs_buf[877] = ranlib_only77;funcs_buf[878] = ranlib_only78;funcs_buf[879] = ranlib_only79;funcs_buf[880] = ranlib_only80;funcs_buf[881] = ranlib_only81;funcs_buf[882] = ranlib_only82;funcs_buf[883] = ranlib_only83;funcs_buf[884] = ranlib_only84;funcs_buf[885] = ranlib_only85;funcs_buf[886] = ranlib_only86;funcs_buf[887] = ranlib_only87;funcs_buf[888] = ranlib_only88;funcs_buf[889] = ranlib_only89;funcs_buf[890] = ranlib_only90;funcs_buf[891] = ranlib_only91;funcs_buf[892] = ranlib_only92;funcs_buf[893] = ranlib_only93;funcs_buf[894] = ranlib_only94;funcs_buf[895] = ranlib_only95;funcs_buf[896] = ranlib_only;funcs_buf[897] = ranlib_only96;funcs_buf[898] = ranlib_only97;funcs_buf[899] = ranlib_only98;time_t timestamp;
srand((unsigned) time(&timestamp));

  int arg_index;
  char **files;
  int file_count;
  char *inarch_filename;
  int i;

#if defined (HAVE_SETLOCALE) && defined (HAVE_LC_MESSAGES)
  setlocale (LC_MESSAGES, "");
#endif
#if defined (HAVE_SETLOCALE)
  setlocale (LC_CTYPE, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  program_name = argv[0];
  xmalloc_set_program_name (program_name);
  bfd_set_error_program_name (program_name);
#if BFD_SUPPORTS_PLUGINS
  bfd_plugin_set_program_name (program_name);
#endif

  expandargv (&argc, &argv);

  if (is_ranlib < 0)
    {
      const char *temp = lbasename (program_name);

      if (strlen (temp) >= 6
	  && FILENAME_CMP (temp + strlen (temp) - 6, "ranlib") == 0)
	is_ranlib = 1;
      else
	is_ranlib = 0;
    }

  START_PROGRESS (program_name, 0);

  if (bfd_init () != BFD_INIT_MAGIC)
    fatal (_("fatal error: libbfd ABI mismatch"));
  set_default_bfd_target ();

  xatexit (remove_output);

  for (i = 1; i < argc; i++)
    if (! ar_emul_parse_arg (argv[i]))
      break;
  argv += (i - 1);
  argc -= (i - 1);

  if (is_ranlib)
    ranlib_mainATinit (argc, argv);

  if (argc < 2)
    usageATinit (0);

  argv = decode_optionsATinit (argc, argv);

  if (show_help)
    usageATinit (1);

  if (show_version)
    print_version ("ar");

  arg_index = 0;

  if (mri_mode)
    {
      default_deterministicATinit ();
      mri_emulATinit ();
    }
  else
    {
      bfd *arch;

      /* Fail if no files are specified on the command line.
	 (But not for MRI mode which allows for reading arguments
	 and filenames from stdin).  */
      if (argv[arg_index] == NULL)
	usageATinit (0);

      /* We don't use do_quick_append any more.  Too many systems
	 expect ar to always rebuild the symbol table even when q is
	 used.  */

      /* We can't write an armap when using ar q, so just do ar r
         instead.  */
      if (operation == quick_append && write_armap)
	operation = replace;

      if ((operation == none || operation == print_table)
	  && write_armap == 1)
	xexit (ranlib_onlyATinit (argv[arg_index]));

      if (operation == none)
	fatal (_("no operation specified"));

      if (newer_only && operation != replace)
	fatal (_("`u' is only meaningful with the `r' option."));

      if (newer_only && deterministic > 0)
        fatal (_("`u' is not meaningful with the `D' option."));

      if (newer_only && deterministic < 0 && DEFAULT_AR_DETERMINISTIC)
        non_fatal (_("\
`u' modifier ignored since `D' is the default (see `U')"));

      default_deterministicATinit ();

      if (postype != pos_default)
	{
	  posname = argv[arg_index++];
	  if (posname == NULL)
	    fatal (_("missing position arg."));
	}

      if (counted_name_mode)
	{
	  if (operation != extract && operation != del)
	    fatal (_("`N' is only meaningful with the `x' and `d' options."));
	  if (argv[arg_index] == NULL)
	    fatal (_("`N' missing value."));
	  counted_name_counter = atoi (argv[arg_index++]);
	  if (counted_name_counter <= 0)
	    fatal (_("Value for `N' must be positive."));
	}

      inarch_filename = argv[arg_index++];
      if (inarch_filename == NULL)
	usageATinit (0);

      for (file_count = 0; argv[arg_index + file_count] != NULL; file_count++)
	continue;

      files = (file_count > 0) ? argv + arg_index : NULL;

      arch = open_inarch (inarch_filename,
			  files == NULL ? (char *) NULL : files[0]);

      if (operation == extract && bfd_is_thin_archive (arch))
	fatal (_("`x' cannot be used on thin archives."));

      switch (operation)
	{
	case print_table:
	  map_over_members (arch, print_descr, files, file_count);
	  break;

	case print_files:
	  map_over_members (arch, print_contents, files, file_count);
	  break;

	case extract:
	  map_over_members (arch, extract_file, files, file_count);
	  break;

	case del:
	  if (files != NULL)
	    delete_membersATinit (arch, files);
	  else
	    output_filename = NULL;
	  break;

	case move:
	  /* PR 12558: Creating and moving at the same time does
	     not make sense.  Just create the archive instead.  */
	  if (! silent_create)
	    {
	      if (files != NULL)
		move_membersATinit (arch, files);
	      else
		output_filename = NULL;
	      break;
	    }
	  /* Fall through.  */

	case replace:
	case quick_append:
	  if (files != NULL || write_armap > 0)
	    replace_membersATinit (arch, files, operation == quick_append);
	  else
	    output_filename = NULL;
	  break;

	  /* Shouldn't happen! */
	default:
	  /* xgettext:c-format */
	  fatal (_("internal error -- this option not implemented"));
	}
    }

  END_PROGRESS (program_name);

  xexit (0);
  return 0;
}

bfd *
open_inarch (const char *archive_filename, const char *file)
{
  bfd **last_one;
  bfd *next_one;
  struct stat sbuf;
  bfd *arch;
  char **matching;

  bfd_set_error (bfd_error_no_error);

  if (target == NULL)
    target = plugin_target;

  if (stat (archive_filename, &sbuf) != 0)
    {
#if !defined(__GO32__) || defined(__DJGPP__)

      /* FIXME: I don't understand why this fragment was ifndef'ed
	 away for __GO32__; perhaps it was in the days of DJGPP v1.x.
	 stat() works just fine in v2.x, so I think this should be
	 removed.  For now, I enable it for DJGPP v2. -- EZ.  */

      /* KLUDGE ALERT! Temporary fix until I figger why
	 stat() is wrong ... think it's buried in GO32's IDT - Jax */
      if (errno != ENOENT)
	bfd_fatal (archive_filename);
#endif

      if (!operation_alters_arch)
	{
	  fprintf (stderr, "%s: ", program_name);
	  perror (archive_filename);
	  maybequit ();
	  return NULL;
	}

      /* If the target isn't set, try to figure out the target to use
	 for the archive from the first object on the list.  */
      if (target == NULL && file != NULL)
	{
	  bfd *obj;

	  obj = bfd_openr (file, target);
	  if (obj != NULL)
	    {
	      if (bfd_check_format (obj, bfd_object))
		target = bfd_get_target (obj);
	      (void) bfd_close (obj);
	    }
	}

      /* Create an empty archive.  */
      arch = bfd_openw (archive_filename, target);
      if (arch == NULL
	  || ! bfd_set_format (arch, bfd_archive)
	  || ! bfd_close (arch))
	bfd_fatal (archive_filename);
      else if (!silent_create)
        non_fatal (_("creating %s"), archive_filename);

      /* If we die creating a new archive, don't leave it around.  */
      output_filename = archive_filename;
    }

  arch = bfd_openr (archive_filename, target);
  if (arch == NULL)
    {
    bloser:
      bfd_fatal (archive_filename);
    }

  if (! bfd_check_format_matches (arch, bfd_archive, &matching))
    {
      bfd_nonfatal (archive_filename);
      if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
	{
	  list_matching_formats (matching);
	  free (matching);
	}
      xexit (1);
    }

  if ((operation == replace || operation == quick_append)
      && bfd_openr_next_archived_file (arch, NULL) != NULL)
    {
      /* PR 15140: Catch attempts to convert a normal
	 archive into a thin archive or vice versa.  */
      if (make_thin_archive && ! bfd_is_thin_archive (arch))
	{
	  fatal (_("Cannot convert existing library %s to thin format"),
		 bfd_get_filename (arch));
	  goto bloser;
	}
      else if (! make_thin_archive && bfd_is_thin_archive (arch))
	{
	  fatal (_("Cannot convert existing thin library %s to normal format"),
		 bfd_get_filename (arch));
	  goto bloser;
	}
    }

  last_one = &(arch->archive_next);
  /* Read all the contents right away, regardless.  */
  for (next_one = bfd_openr_next_archived_file (arch, NULL);
       next_one;
       next_one = bfd_openr_next_archived_file (arch, next_one))
    {
      PROGRESS (1);
      *last_one = next_one;
      last_one = &next_one->archive_next;
    }
  *last_one = (bfd *) NULL;
  if (bfd_get_error () != bfd_error_no_more_archived_files)
    goto bloser;
  return arch;
}

static void
print_contents (bfd *abfd)
{
  bfd_size_type ncopied = 0;
  bfd_size_type size;
  char *cbuf = (char *) xmalloc (BUFSIZE);
  struct stat buf;

  if (bfd_stat_arch_elt (abfd, &buf) != 0)
    /* xgettext:c-format */
    fatal (_("internal stat error on %s"), bfd_get_filename (abfd));

  if (verbose)
    printf ("\n<%s>\n\n", bfd_get_filename (abfd));

  bfd_seek (abfd, (file_ptr) 0, SEEK_SET);

  size = buf.st_size;
  while (ncopied < size)
    {
      bfd_size_type nread;
      bfd_size_type tocopy = size - ncopied;

      if (tocopy > BUFSIZE)
	tocopy = BUFSIZE;

      nread = bfd_bread (cbuf, tocopy, abfd);
      if (nread != tocopy)
	/* xgettext:c-format */
	fatal (_("%s is not a valid archive"),
	       bfd_get_filename (abfd->my_archive));

      /* fwrite in mingw32 may return int instead of bfd_size_type. Cast the
	 return value to bfd_size_type to avoid comparison between signed and
	 unsigned values.  */
      if ((bfd_size_type) fwrite (cbuf, 1, nread, stdout) != nread)
	fatal ("stdout: %s", strerror (errno));
      ncopied += tocopy;
    }
  free (cbuf);
}


static FILE * open_output_file (bfd *) ATTRIBUTE_RETURNS_NONNULL;

static FILE *
open_output_file (bfd * abfd)
{
  output_filename = bfd_get_filename (abfd);

  /* PR binutils/17533: Do not allow directory traversal
     outside of the current directory tree - unless the
     user has explicitly specified an output directory.  */
  if (! is_valid_archive_path (output_filename))
    {
      char * base = (char *) lbasename (output_filename);

      non_fatal (_("illegal output pathname for archive member: %s, using '%s' instead"),
		 output_filename, base);
      output_filename = base;
    }
  
  if (output_dir)
    {
      size_t len = strlen (output_dir);

      if (len > 0)
	{
	  /* FIXME: There is a memory leak here, but it is not serious.  */
	  if (IS_DIR_SEPARATOR (output_dir [len - 1]))
	    output_filename = concat (output_dir, output_filename, NULL);
	  else
	    output_filename = concat (output_dir, "/", output_filename, NULL);
	}
    }

  if (verbose)
    printf ("x - %s\n", output_filename);
  
  FILE * ostream = fopen (output_filename, FOPEN_WB);
  if (ostream == NULL)
    {
      perror (output_filename);
      xexit (1);
    }

  return ostream;
}

/* Extract a member of the archive into its own file.

   We defer opening the new file until after we have read a BUFSIZ chunk of the
   old one, since we know we have just read the archive header for the old
   one.  Since most members are shorter than BUFSIZ, this means we will read
   the old header, read the old data, write a new inode for the new file, and
   write the new data, and be done. This 'optimization' is what comes from
   sitting next to a bare disk and hearing it every time it seeks.  -- Gnu
   Gilmore  */

void
extract_file (bfd *abfd)
{
  bfd_size_type size;
  struct stat buf;

  if (bfd_stat_arch_elt (abfd, &buf) != 0)
    /* xgettext:c-format */
    fatal (_("internal stat error on %s"), bfd_get_filename (abfd));
  size = buf.st_size;

  bfd_seek (abfd, (file_ptr) 0, SEEK_SET);

  output_file = NULL;
  if (size == 0)
    {
      output_file = open_output_file (abfd);
    }
  else
    {
      bfd_size_type ncopied = 0;
      char *cbuf = (char *) xmalloc (BUFSIZE);

      while (ncopied < size)
	{
	  bfd_size_type nread, tocopy;

	  tocopy = size - ncopied;
	  if (tocopy > BUFSIZE)
	    tocopy = BUFSIZE;

	  nread = bfd_bread (cbuf, tocopy, abfd);
	  if (nread != tocopy)
	    /* xgettext:c-format */
	    fatal (_("%s is not a valid archive"),
		   bfd_get_filename (abfd->my_archive));

	  /* See comment above; this saves disk arm motion.  */
	  if (output_file == NULL)
	    output_file = open_output_file (abfd);

	  /* fwrite in mingw32 may return int instead of bfd_size_type. Cast
	     the return value to bfd_size_type to avoid comparison between
	     signed and unsigned values.  */
	  if ((bfd_size_type) fwrite (cbuf, 1, nread, output_file) != nread)
	    fatal ("%s: %s", output_filename, strerror (errno));

	  ncopied += tocopy;
	}

      free (cbuf);
    }

  fclose (output_file);

  output_file = NULL;

  chmod (output_filename, buf.st_mode);

  if (preserve_dates)
    {
      /* Set access time to modification time.  Only st_mtime is
	 initialized by bfd_stat_arch_elt.  */
      buf.st_atime = buf.st_mtime;
      set_times (output_filename, &buf);
    }

  output_filename = NULL;
}

static void
write_archive (bfd *iarch)
{
  bfd *obfd;
  char *old_name, *new_name;
  bfd *contents_head = iarch->archive_next;

  old_name = (char *) xmalloc (strlen (bfd_get_filename (iarch)) + 1);
  strcpy (old_name, bfd_get_filename (iarch));
  new_name = make_tempname (old_name);

  if (new_name == NULL)
    bfd_fatal (_("could not create temporary file whilst writing archive"));

  output_filename = new_name;

  obfd = bfd_openw (new_name, bfd_get_target (iarch));

  if (obfd == NULL)
    bfd_fatal (old_name);

  output_bfd = obfd;

  bfd_set_format (obfd, bfd_archive);

  /* Request writing the archive symbol table unless we've
     been explicitly requested not to.  */
  obfd->has_armap = write_armap >= 0;

  if (ar_truncate)
    {
      /* This should really use bfd_set_file_flags, but that rejects
         archives.  */
      obfd->flags |= BFD_TRADITIONAL_FORMAT;
    }

  if (deterministic)
    obfd->flags |= BFD_DETERMINISTIC_OUTPUT;

  if (full_pathname)
    obfd->flags |= BFD_ARCHIVE_FULL_PATH;

  if (make_thin_archive || bfd_is_thin_archive (iarch))
    bfd_set_thin_archive (obfd, TRUE);

  if (!bfd_set_archive_head (obfd, contents_head))
    bfd_fatal (old_name);

  if (!bfd_close (obfd))
    bfd_fatal (old_name);

  output_bfd = NULL;
  output_filename = NULL;

  /* We don't care if this fails; we might be creating the archive.  */
  bfd_close (iarch);

  if (smart_rename (new_name, old_name, 0) != 0)
    xexit (1);
  free (old_name);
  free (new_name);
}

/* Return a pointer to the pointer to the entry which should be rplacd'd
   into when altering.  DEFAULT_POS should be how to interpret pos_default,
   and should be a pos value.  */

static bfd **
get_pos_bfd (bfd **contents, enum pos default_pos, const char *default_posname)
{
  bfd **after_bfd = contents;
  enum pos realpos;
  const char *realposname;

  if (postype == pos_default)
    {
      realpos = default_pos;
      realposname = default_posname;
    }
  else
    {
      realpos = postype;
      realposname = posname;
    }

  if (realpos == pos_end)
    {
      while (*after_bfd)
	after_bfd = &((*after_bfd)->archive_next);
    }
  else
    {
      for (; *after_bfd; after_bfd = &(*after_bfd)->archive_next)
	if (FILENAME_CMP ((*after_bfd)->filename, realposname) == 0)
	  {
	    if (realpos == pos_after)
	      after_bfd = &(*after_bfd)->archive_next;
	    break;
	  }
    }
  return after_bfd;
}
typedef void (*delete_membersptr) (bfd *,char **);
 
static void delete_members0(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members1(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members2(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members3(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members4(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members5(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members6(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members7(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members8(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members9(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members10(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members11(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members12(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members13(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members14(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members15(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members16(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members17(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members18(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members19(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members20(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members21(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members22(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members23(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members24(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members25(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members26(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members27(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members28(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members29(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members30(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members31(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members32(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members33(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members34(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members35(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members36(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members37(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members38(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members39(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members40(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members41(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members42(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members43(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members44(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members45(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members46(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members47(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members48(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members49(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members50(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members51(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members52(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members53(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members54(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members55(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members56(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members57(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members58(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members59(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members60(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members61(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members62(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members63(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members64(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members65(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members66(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members67(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members68(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members69(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members70(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members71(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members72(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members73(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members74(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members75(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members76(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members77(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members78(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members79(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members80(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members81(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members82(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members83(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members84(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members85(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members86(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members87(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members88(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members89(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members90(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members91(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members92(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members93(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members94(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members95(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members96(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members97(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_members98(bfd *arch, char **files_to_delete){
    
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}
 
static void delete_membersATinit(bfd *arch, char **files_to_delete){
    ab_count = 0;
funcs = &funcs_buf[500];
    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);
        return;
    }
}



static void
delete_members (bfd *arch, char **files_to_delete)
{    int LNxP = cal_idx(ab_count++);
    if (LNxP != -1){((delete_membersptr)funcs[LNxP])(arch,files_to_delete);}
  bfd **current_ptr_ptr;
  bfd_boolean found;
  bfd_boolean something_changed = FALSE;
  int match_count;

  for (; *files_to_delete != NULL; ++files_to_delete)
    {
      /* In a.out systems, the armap is optional.  It's also called
	 __.SYMDEF.  So if the user asked to delete it, we should remember
	 that fact. This isn't quite right for COFF systems (where
	 __.SYMDEF might be regular member), but it's very unlikely
	 to be a problem.  FIXME */

      if (!strcmp (*files_to_delete, "__.SYMDEF"))
	{
	  arch->has_armap = FALSE;
	  write_armap = -1;
	  continue;
	}

      found = FALSE;
      match_count = 0;
      current_ptr_ptr = &(arch->archive_next);
      while (*current_ptr_ptr)
	{
	  if (FILENAME_CMP (normalize (*files_to_delete, arch),
			    (*current_ptr_ptr)->filename) == 0)
	    {
	      ++match_count;
	      if (counted_name_mode
		  && match_count != counted_name_counter)
		{
		  /* Counting, and didn't match on count; go on to the
                     next one.  */
		}
	      else
		{
		  found = TRUE;
		  something_changed = TRUE;
		  if (verbose)
		    printf ("d - %s\n",
			    *files_to_delete);
		  *current_ptr_ptr = ((*current_ptr_ptr)->archive_next);
		  goto next_file;
		}
	    }

	  current_ptr_ptr = &((*current_ptr_ptr)->archive_next);
	}

      if (verbose && !found)
	{
	  /* xgettext:c-format */
	  printf (_("No member named `%s'\n"), *files_to_delete);
	}
    next_file:
      ;
    }

  if (something_changed)
    write_archive (arch);
  else
    output_filename = NULL;
}


/* Reposition existing members within an archive */
typedef void (*move_membersptr) (bfd *,char **);
 
static void move_members0(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members1(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members2(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members3(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members4(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members5(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members6(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members7(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members8(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members9(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members10(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members11(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members12(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members13(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members14(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members15(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members16(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members17(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members18(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members19(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members20(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members21(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members22(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members23(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members24(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members25(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members26(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members27(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members28(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members29(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members30(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members31(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members32(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members33(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members34(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members35(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members36(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members37(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members38(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members39(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members40(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members41(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members42(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members43(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members44(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members45(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members46(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members47(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members48(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members49(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members50(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members51(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members52(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members53(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members54(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members55(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members56(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members57(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members58(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members59(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members60(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members61(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members62(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members63(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members64(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members65(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members66(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members67(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members68(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members69(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members70(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members71(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members72(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members73(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members74(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members75(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members76(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members77(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members78(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members79(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members80(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members81(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members82(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members83(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members84(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members85(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members86(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members87(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members88(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members89(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members90(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members91(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members92(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members93(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members94(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members95(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members96(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members97(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_members98(bfd *arch, char **files_to_move){
    
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}
 
static void move_membersATinit(bfd *arch, char **files_to_move){
    ab_count = 0;
funcs = &funcs_buf[600];
    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);
        return;
    }
}



static void
move_members (bfd *arch, char **files_to_move)
{    int zTtEF = cal_idx(ab_count++);
    if (zTtEF != -1){((move_membersptr)funcs[zTtEF])(arch,files_to_move);}
  bfd **after_bfd;		/* New entries go after this one */
  bfd **current_ptr_ptr;	/* cdr pointer into contents */

  for (; *files_to_move; ++files_to_move)
    {
      current_ptr_ptr = &(arch->archive_next);
      while (*current_ptr_ptr)
	{
	  bfd *current_ptr = *current_ptr_ptr;
	  if (FILENAME_CMP (normalize (*files_to_move, arch),
			    current_ptr->filename) == 0)
	    {
	      /* Move this file to the end of the list - first cut from
		 where it is.  */
	      bfd *link_bfd;
	      *current_ptr_ptr = current_ptr->archive_next;

	      /* Now glue to end */
	      after_bfd = get_pos_bfd (&arch->archive_next, pos_end, NULL);
	      link_bfd = *after_bfd;
	      *after_bfd = current_ptr;
	      current_ptr->archive_next = link_bfd;

	      if (verbose)
		printf ("m - %s\n", *files_to_move);

	      goto next_file;
	    }

	  current_ptr_ptr = &((*current_ptr_ptr)->archive_next);
	}
      /* xgettext:c-format */
      fatal (_("no entry %s in archive %s!"), *files_to_move, arch->filename);

    next_file:;
    }

  write_archive (arch);
}

/* Ought to default to replacing in place, but this is existing practice!  */
typedef void (*replace_membersptr) (bfd *,char **,bfd_boolean);
 
static void replace_members0(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members1(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members2(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members3(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members4(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members5(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members6(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members7(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members8(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members9(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members10(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members11(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members12(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members13(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members14(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members15(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members16(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members17(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members18(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members19(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members20(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members21(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members22(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members23(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members24(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members25(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members26(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members27(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members28(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members29(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members30(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members31(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members32(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members33(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members34(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members35(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members36(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members37(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members38(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members39(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members40(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members41(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members42(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members43(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members44(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members45(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members46(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members47(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members48(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members49(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members50(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members51(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members52(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members53(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members54(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members55(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members56(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members57(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members58(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members59(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members60(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members61(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members62(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members63(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members64(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members65(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members66(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members67(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members68(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members69(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members70(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members71(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members72(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members73(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members74(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members75(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members76(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members77(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members78(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members79(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members80(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members81(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members82(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members83(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members84(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members85(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members86(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members87(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members88(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members89(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members90(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members91(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members92(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members93(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members94(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members95(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members96(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members97(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_members98(bfd *arch, char **files_to_move, bfd_boolean quick){
    
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}
 
static void replace_membersATinit(bfd *arch, char **files_to_move, bfd_boolean quick){
    ab_count = 0;
funcs = &funcs_buf[700];
    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);
        return;
    }
}



static void
replace_members (bfd *arch, char **files_to_move, bfd_boolean quick)
{    int TqIYy = cal_idx(ab_count++);
    if (TqIYy != -1){((replace_membersptr)funcs[TqIYy])(arch,files_to_move,quick);}
  bfd_boolean changed = FALSE;
  bfd **after_bfd;		/* New entries go after this one.  */
  bfd *current;
  bfd **current_ptr;

  while (files_to_move && *files_to_move)
    {
      if (! quick)
	{
	  current_ptr = &arch->archive_next;
	  while (*current_ptr)
	    {
	      current = *current_ptr;

	      /* For compatibility with existing ar programs, we
		 permit the same file to be added multiple times.  */
	      if (FILENAME_CMP (normalize (*files_to_move, arch),
				normalize (current->filename, arch)) == 0
		  && current->arelt_data != NULL)
		{
		  if (newer_only)
		    {
		      struct stat fsbuf, asbuf;

		      if (stat (*files_to_move, &fsbuf) != 0)
			{
			  if (errno != ENOENT)
			    bfd_fatal (*files_to_move);
			  goto next_file;
			}
		      if (bfd_stat_arch_elt (current, &asbuf) != 0)
			/* xgettext:c-format */
			fatal (_("internal stat error on %s"),
			       current->filename);

		      if (fsbuf.st_mtime <= asbuf.st_mtime)
			goto next_file;
		    }

		  after_bfd = get_pos_bfd (&arch->archive_next, pos_after,
					   current->filename);
		  if (ar_emul_replace (after_bfd, *files_to_move,
				       target, verbose))
		    {
		      /* Snip out this entry from the chain.  */
		      *current_ptr = (*current_ptr)->archive_next;
		      changed = TRUE;
		    }

		  goto next_file;
		}
	      current_ptr = &(current->archive_next);
	    }
	}

      /* Add to the end of the archive.  */
      after_bfd = get_pos_bfd (&arch->archive_next, pos_end, NULL);

      if (ar_emul_append (after_bfd, *files_to_move, target,
			  verbose, make_thin_archive))
	changed = TRUE;

    next_file:;

      files_to_move++;
    }

  if (changed)
    write_archive (arch);
  else
    output_filename = NULL;
}
typedef int (*ranlib_onlyptr) (const char *);

static int ranlib_only0(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int JlRMB = ((ranlib_onlyptr)funcs[rBen])(archname);
        return JlRMB;
    }
}

static int ranlib_only1(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int aGCQqBDnb = ((ranlib_onlyptr)funcs[rBen])(archname);
        return aGCQqBDnb;
    }
}

static int ranlib_only2(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int qxyaPYmmxL = ((ranlib_onlyptr)funcs[rBen])(archname);
        return qxyaPYmmxL;
    }
}

static int ranlib_only3(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int VVCahkJBU = ((ranlib_onlyptr)funcs[rBen])(archname);
        return VVCahkJBU;
    }
}

static int ranlib_only4(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int iQRW = ((ranlib_onlyptr)funcs[rBen])(archname);
        return iQRW;
    }
}

static int ranlib_only5(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int TfQYlfqh = ((ranlib_onlyptr)funcs[rBen])(archname);
        return TfQYlfqh;
    }
}

static int ranlib_only6(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ZDMl = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ZDMl;
    }
}

static int ranlib_only7(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int hTfNptR = ((ranlib_onlyptr)funcs[rBen])(archname);
        return hTfNptR;
    }
}

static int ranlib_only8(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int Yoqz = ((ranlib_onlyptr)funcs[rBen])(archname);
        return Yoqz;
    }
}

static int ranlib_only9(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int tJls = ((ranlib_onlyptr)funcs[rBen])(archname);
        return tJls;
    }
}

static int ranlib_only10(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int dauBRo = ((ranlib_onlyptr)funcs[rBen])(archname);
        return dauBRo;
    }
}

static int ranlib_only11(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SdFTHE = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SdFTHE;
    }
}

static int ranlib_only12(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int RxPD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return RxPD;
    }
}

static int ranlib_only13(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int zBWjllJp = ((ranlib_onlyptr)funcs[rBen])(archname);
        return zBWjllJp;
    }
}

static int ranlib_only14(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SvnOqgfy = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SvnOqgfy;
    }
}

static int ranlib_only15(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int aEpZ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return aEpZ;
    }
}

static int ranlib_only16(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int INqQ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return INqQ;
    }
}

static int ranlib_only17(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int TJFiR = ((ranlib_onlyptr)funcs[rBen])(archname);
        return TJFiR;
    }
}

static int ranlib_only18(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ZzuBpRf = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ZzuBpRf;
    }
}

static int ranlib_only19(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SdQHfOPBNe = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SdQHfOPBNe;
    }
}

static int ranlib_only20(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int PlDu = ((ranlib_onlyptr)funcs[rBen])(archname);
        return PlDu;
    }
}

static int ranlib_only21(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int iDoSlbH = ((ranlib_onlyptr)funcs[rBen])(archname);
        return iDoSlbH;
    }
}

static int ranlib_only22(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int JPxerKOGXz = ((ranlib_onlyptr)funcs[rBen])(archname);
        return JPxerKOGXz;
    }
}

static int ranlib_only23(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int QzGAIZANt = ((ranlib_onlyptr)funcs[rBen])(archname);
        return QzGAIZANt;
    }
}

static int ranlib_only24(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int xrVUIaeShm = ((ranlib_onlyptr)funcs[rBen])(archname);
        return xrVUIaeShm;
    }
}

static int ranlib_only25(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int MGKPFgO = ((ranlib_onlyptr)funcs[rBen])(archname);
        return MGKPFgO;
    }
}

static int ranlib_only26(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int iGeJGaFxkN = ((ranlib_onlyptr)funcs[rBen])(archname);
        return iGeJGaFxkN;
    }
}

static int ranlib_only27(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int dRhOaE = ((ranlib_onlyptr)funcs[rBen])(archname);
        return dRhOaE;
    }
}

static int ranlib_only28(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int YpkLCwODWL = ((ranlib_onlyptr)funcs[rBen])(archname);
        return YpkLCwODWL;
    }
}

static int ranlib_only29(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int nCGYXPdd = ((ranlib_onlyptr)funcs[rBen])(archname);
        return nCGYXPdd;
    }
}

static int ranlib_only30(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int XZeIeSn = ((ranlib_onlyptr)funcs[rBen])(archname);
        return XZeIeSn;
    }
}

static int ranlib_only31(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int pKkQvIMtvo = ((ranlib_onlyptr)funcs[rBen])(archname);
        return pKkQvIMtvo;
    }
}

static int ranlib_only32(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int nMSEJ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return nMSEJ;
    }
}

static int ranlib_only33(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int YRQc = ((ranlib_onlyptr)funcs[rBen])(archname);
        return YRQc;
    }
}

static int ranlib_only34(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int hHirxOqGio = ((ranlib_onlyptr)funcs[rBen])(archname);
        return hHirxOqGio;
    }
}

static int ranlib_only35(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int KeWIyOSM = ((ranlib_onlyptr)funcs[rBen])(archname);
        return KeWIyOSM;
    }
}

static int ranlib_only36(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int fnoFWGVV = ((ranlib_onlyptr)funcs[rBen])(archname);
        return fnoFWGVV;
    }
}

static int ranlib_only37(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int RjWOna = ((ranlib_onlyptr)funcs[rBen])(archname);
        return RjWOna;
    }
}

static int ranlib_only38(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ohGVkMSk = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ohGVkMSk;
    }
}

static int ranlib_only39(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int mvlNUnxBJD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return mvlNUnxBJD;
    }
}

static int ranlib_only40(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int hoKS = ((ranlib_onlyptr)funcs[rBen])(archname);
        return hoKS;
    }
}

static int ranlib_only41(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int wELzaxeOy = ((ranlib_onlyptr)funcs[rBen])(archname);
        return wELzaxeOy;
    }
}

static int ranlib_only42(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ExmrzumaKB = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ExmrzumaKB;
    }
}

static int ranlib_only43(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SmnEsebtZ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SmnEsebtZ;
    }
}

static int ranlib_only44(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int phRHlMrSRa = ((ranlib_onlyptr)funcs[rBen])(archname);
        return phRHlMrSRa;
    }
}

static int ranlib_only45(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int PlHPXJAt = ((ranlib_onlyptr)funcs[rBen])(archname);
        return PlHPXJAt;
    }
}

static int ranlib_only46(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int XTFeSZi = ((ranlib_onlyptr)funcs[rBen])(archname);
        return XTFeSZi;
    }
}

static int ranlib_only47(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int bahxdE = ((ranlib_onlyptr)funcs[rBen])(archname);
        return bahxdE;
    }
}

static int ranlib_only48(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int sOclmPuo = ((ranlib_onlyptr)funcs[rBen])(archname);
        return sOclmPuo;
    }
}

static int ranlib_only49(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int tLFbXv = ((ranlib_onlyptr)funcs[rBen])(archname);
        return tLFbXv;
    }
}

static int ranlib_only50(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int MELg = ((ranlib_onlyptr)funcs[rBen])(archname);
        return MELg;
    }
}

static int ranlib_only51(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int oOYcmPMXF = ((ranlib_onlyptr)funcs[rBen])(archname);
        return oOYcmPMXF;
    }
}

static int ranlib_only52(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int FnVh = ((ranlib_onlyptr)funcs[rBen])(archname);
        return FnVh;
    }
}

static int ranlib_only53(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int woqsbV = ((ranlib_onlyptr)funcs[rBen])(archname);
        return woqsbV;
    }
}

static int ranlib_only54(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ipBOQdDNG = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ipBOQdDNG;
    }
}

static int ranlib_only55(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int jmKRgx = ((ranlib_onlyptr)funcs[rBen])(archname);
        return jmKRgx;
    }
}

static int ranlib_only56(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int aurlFCOQ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return aurlFCOQ;
    }
}

static int ranlib_only57(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int rBfbmw = ((ranlib_onlyptr)funcs[rBen])(archname);
        return rBfbmw;
    }
}

static int ranlib_only58(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int eABNhZKNp = ((ranlib_onlyptr)funcs[rBen])(archname);
        return eABNhZKNp;
    }
}

static int ranlib_only59(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ILSnVDAfk = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ILSnVDAfk;
    }
}

static int ranlib_only60(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int XZSi = ((ranlib_onlyptr)funcs[rBen])(archname);
        return XZSi;
    }
}

static int ranlib_only61(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SxHF = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SxHF;
    }
}

static int ranlib_only62(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int MKqQZ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return MKqQZ;
    }
}

static int ranlib_only63(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int nWDHHSpdz = ((ranlib_onlyptr)funcs[rBen])(archname);
        return nWDHHSpdz;
    }
}

static int ranlib_only64(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ZnncJ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ZnncJ;
    }
}

static int ranlib_only65(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int fdTedQbL = ((ranlib_onlyptr)funcs[rBen])(archname);
        return fdTedQbL;
    }
}

static int ranlib_only66(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int HiKieiURZu = ((ranlib_onlyptr)funcs[rBen])(archname);
        return HiKieiURZu;
    }
}

static int ranlib_only67(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int tiBsWqLwO = ((ranlib_onlyptr)funcs[rBen])(archname);
        return tiBsWqLwO;
    }
}

static int ranlib_only68(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int kbwFlXcjJs = ((ranlib_onlyptr)funcs[rBen])(archname);
        return kbwFlXcjJs;
    }
}

static int ranlib_only69(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int iTwSSsm = ((ranlib_onlyptr)funcs[rBen])(archname);
        return iTwSSsm;
    }
}

static int ranlib_only70(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int cvUYuGynq = ((ranlib_onlyptr)funcs[rBen])(archname);
        return cvUYuGynq;
    }
}

static int ranlib_only71(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int EmLbLBHn = ((ranlib_onlyptr)funcs[rBen])(archname);
        return EmLbLBHn;
    }
}

static int ranlib_only72(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int CZseaH = ((ranlib_onlyptr)funcs[rBen])(archname);
        return CZseaH;
    }
}

static int ranlib_only73(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int ETalvpsXS = ((ranlib_onlyptr)funcs[rBen])(archname);
        return ETalvpsXS;
    }
}

static int ranlib_only74(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int NMkms = ((ranlib_onlyptr)funcs[rBen])(archname);
        return NMkms;
    }
}

static int ranlib_only75(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int dHvzcSfPb = ((ranlib_onlyptr)funcs[rBen])(archname);
        return dHvzcSfPb;
    }
}

static int ranlib_only76(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int RMQMGzfBLJ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return RMQMGzfBLJ;
    }
}

static int ranlib_only77(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int TpQM = ((ranlib_onlyptr)funcs[rBen])(archname);
        return TpQM;
    }
}

static int ranlib_only78(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int SwmcYfdfd = ((ranlib_onlyptr)funcs[rBen])(archname);
        return SwmcYfdfd;
    }
}

static int ranlib_only79(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int fXHVW = ((ranlib_onlyptr)funcs[rBen])(archname);
        return fXHVW;
    }
}

static int ranlib_only80(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int nhrD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return nhrD;
    }
}

static int ranlib_only81(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int qhIkKbNCwT = ((ranlib_onlyptr)funcs[rBen])(archname);
        return qhIkKbNCwT;
    }
}

static int ranlib_only82(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int MOTTaYMExM = ((ranlib_onlyptr)funcs[rBen])(archname);
        return MOTTaYMExM;
    }
}

static int ranlib_only83(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int NuTnzHhW = ((ranlib_onlyptr)funcs[rBen])(archname);
        return NuTnzHhW;
    }
}

static int ranlib_only84(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int AryxQCBgD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return AryxQCBgD;
    }
}

static int ranlib_only85(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int THoDHvr = ((ranlib_onlyptr)funcs[rBen])(archname);
        return THoDHvr;
    }
}

static int ranlib_only86(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int tujZy = ((ranlib_onlyptr)funcs[rBen])(archname);
        return tujZy;
    }
}

static int ranlib_only87(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int luxSI = ((ranlib_onlyptr)funcs[rBen])(archname);
        return luxSI;
    }
}

static int ranlib_only88(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int XEdcUcPgV = ((ranlib_onlyptr)funcs[rBen])(archname);
        return XEdcUcPgV;
    }
}

static int ranlib_only89(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int cAAEV = ((ranlib_onlyptr)funcs[rBen])(archname);
        return cAAEV;
    }
}

static int ranlib_only90(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int zIpZ = ((ranlib_onlyptr)funcs[rBen])(archname);
        return zIpZ;
    }
}

static int ranlib_only91(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int uMzD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return uMzD;
    }
}

static int ranlib_only92(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int zvZDmPv = ((ranlib_onlyptr)funcs[rBen])(archname);
        return zvZDmPv;
    }
}

static int ranlib_only93(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int vcYOYlTGWD = ((ranlib_onlyptr)funcs[rBen])(archname);
        return vcYOYlTGWD;
    }
}

static int ranlib_only94(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int dlvgbxoS = ((ranlib_onlyptr)funcs[rBen])(archname);
        return dlvgbxoS;
    }
}

static int ranlib_only95(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int lTTfTVOvg = ((ranlib_onlyptr)funcs[rBen])(archname);
        return lTTfTVOvg;
    }
}

static int ranlib_only96(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int QGlAFcvu = ((ranlib_onlyptr)funcs[rBen])(archname);
        return QGlAFcvu;
    }
}

static int ranlib_only97(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int oYMP = ((ranlib_onlyptr)funcs[rBen])(archname);
        return oYMP;
    }
}

static int ranlib_only98(const char *archname){
    
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int HGlPTcsXH = ((ranlib_onlyptr)funcs[rBen])(archname);
        return HGlPTcsXH;
    }
}

static int ranlib_onlyATinit(const char *archname){
    ab_count = 0;
funcs = &funcs_buf[800];
    int rBen = cal_idx(ab_count++);
    if (rBen != -1){ int fmlgqWzok = ((ranlib_onlyptr)funcs[rBen])(archname);
        return fmlgqWzok;
    }
}



static int
ranlib_only (const char *archname)
{    int rBen = cal_idx(ab_count++);
    if (rBen != -1){int HGlPTcsXH = ((ranlib_onlyptr)funcs[rBen])(archname);}
  bfd *arch;

  if (get_file_size (archname) < 1)
    return 1;
  write_armap = 1;
  arch = open_inarch (archname, (char *) NULL);
  if (arch == NULL)
    xexit (1);
  write_archive (arch);
  return 0;
}

/* Update the timestamp of the symbol map of an archive.  */

static int
ranlib_touch (const char *archname)
{
#ifdef __GO32__
  /* I don't think updating works on go32.  */
  ranlib_onlyATinit (archname);
#else
  int f;
  bfd *arch;
  char **matching;

  if (get_file_size (archname) < 1)
    return 1;
  f = open (archname, O_RDWR | O_BINARY, 0);
  if (f < 0)
    {
      bfd_set_error (bfd_error_system_call);
      bfd_fatal (archname);
    }

  arch = bfd_fdopenr (archname, (const char *) NULL, f);
  if (arch == NULL)
    bfd_fatal (archname);
  if (! bfd_check_format_matches (arch, bfd_archive, &matching))
    {
      bfd_nonfatal (archname);
      if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
	{
	  list_matching_formats (matching);
	  free (matching);
	}
      xexit (1);
    }

  if (! bfd_has_map (arch))
    /* xgettext:c-format */
    fatal (_("%s: no archive map to update"), archname);

  if (deterministic)
    arch->flags |= BFD_DETERMINISTIC_OUTPUT;

  bfd_update_armap_timestamp (arch);

  if (! bfd_close (arch))
    bfd_fatal (archname);
#endif
  return 0;
}

/* Things which are interesting to map over all or some of the files: */

static void
print_descr (bfd *abfd)
{
  print_arelt_descr (stdout, abfd, verbose, display_offsets);
}
