/*
 
 MacResponse: Incident Response Toolkit for Mac OS X
 
 Copyright (C) 2011 - Assured Information Security, Inc. All rights reserved.

 Authors:
 Christopher Patterson <pattersonc _at_ ainfosec.com>
 
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

// Prevent PPC include
#define _PEXPERT_PPC_BOOT_H_ 1

#include <pexpert/i386/boot.h>

enum {
    //kGetMemoryListSizeCommand = 0,
	//kGetMemoryListItemCommand = 1,
    kMapMemoryCommand = 2,
	kGetKernelBootArgs = 3, // 32-bit kernel support only
};

#define DRIVER_NAME "com_ainfosec_driver_MemoryAccessIOKit" //"com.ainfosec.driver.MemoryAccessIOKit"

typedef struct {
	UInt64 physicalAddress;
	UInt64 requestedLength;
} MemoryAccessIOKit_MapMemoryIn;

typedef struct {
	UInt64 mappedVirtualAddress;
	UInt64 physicalAddress;
	UInt64 requestedLength;
} MemoryAccessIOKit_MapMemoryOut;
