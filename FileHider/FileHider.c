//
//  FileHider.c
//  FileHider
//
//  Created by Folker Schwesinger on 18.05.13.
//  Copyright (c) 2013 rc0r. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t FileHider_start(kmod_info_t * ki, void *d);
kern_return_t FileHider_stop(kmod_info_t *ki, void *d);

kern_return_t FileHider_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t FileHider_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
