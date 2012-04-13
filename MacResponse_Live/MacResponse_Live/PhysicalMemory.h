/*
 
 MacResponse: Incident Response Toolkit for Mac OS X
 
 Copyright (C) 2011 - Assured Information Security, Inc. All rights reserved.

 Authors:
 Christopher Patterson <pattersonc _at_ ainfosec.com>
 Jason Nashold <nasholdj _at_ ainfosec.com>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 
*/

//#define _PEXPERT_PPC_BOOT_H_ 1
//#include <pexpert/i386/boot.h>

#import <Foundation/Foundation.h>

#import "CollectionModule.h"
#include <sys/cdefs.h>
#include <sys/types.h>
#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFRunLoop.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/OSMessageNotification.h>
#include <AvailabilityMacros.h>

#include "../../MemoryAccessIOKit/kext_shared.h"

#define PHYSICALMEMORY_STATUS_ERROR_OPENING_MEMORY_IMAGE	            ((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 1))
#define PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_LOAD_KERNEL_EXTENSION	    ((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 2))
#define PHYSICALMEMORY_STATUS_WARNING_UNABLE_TO_UNLOAD_KERNEL_EXTENSION	((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 3))
#define PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_OPEN_KERNEL_EXTENSION		((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 4))
#define PHYSICALMEMORY_STATUS_DISABLED_64_BIT_KERNEL_UNSUPPORTED		((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 5))
#define PHYSICALMEMORY_STATUS_ERROR_KERNEL_ARCH_UNSUPPORTED				((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 6))
#define PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_BOOT_ARGS			((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 7))
#define PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_EFI_MEMORY_MAP		((collectionmodule_status_t)(COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR - 8))

#define PHYSICALMEMORY_SUBDIRECTORY "PhyiscalMemory"

typedef struct { 
	UInt32 pfnRangeStart; // inclusive
	UInt32 pfnRangeEnd; // exclusive
} PhysicalDRAMRange_t;

#define MAX_DRAM_RANGE_LIST 64

@interface PhysicalMemory : CollectionModule {
	io_connect_t kextConnection;
	io_service_t	kextService;
	void *efiMemoryMap; // malloc'd
	UInt32 efiMemoryRangeListCount;
	PhysicalDRAMRange_t dramRangeList[MAX_DRAM_RANGE_LIST];
	UInt32 dramRangeListCount;
	LiveFile * memoryImageLF;
	UInt64 nextOutputPhysicalAddress; // starting address of next byte out
	UInt64 topPhysicalAddress; // last physical memory address to acquire, used for progress
	struct boot_args bootArgs;
}

@property (readwrite, retain) LiveFile *memoryImageLF;

@end
