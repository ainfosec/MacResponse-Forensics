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

#import "PhysicalMemory.h"
#import "AppController.h"
#import "CaseLog.h"

#include <unistd.h>
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

#define MACRESPONSE_PAGESIZE (4096) /* safe to use... all intel CPUs have page sizes that are at least a multiple of 4K */

@implementation PhysicalMemory

@synthesize memoryImageLF;

- (id)init
{
	[super init];
	[self setModuleName:@"Physical Memory (RAM)"];
	[self setModuleShortName:@"PhysicalMemory"];
	[self setModuleEnabled:TRUE];		
		
	dramRangeListCount = 0;
	
	if (geteuid() == 0)
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_OK];
	}
	else 
	{
		LogDebugObjc(@"Physical memory module - insufficient permissions!\n");
		[self setModuleStatus:COLLECTIONMODULE_STATUS_DISABLED_INSUFFICIENT_PERMISSIONS];
		[self setModuleEnabled:FALSE];
		return self;
	}
	
	if ([Utility getOSXKernelArch] == OSX_Kernel_Arch_x86_64) 
    {
#if 0
		LogDebugObjc(@"x64...\n");
		[self setModuleStatus:PHYSICALMEMORY_STATUS_DISABLED_64_BIT_KERNEL_UNSUPPORTED];
		[self setModuleEnabled:FALSE];
		return self;
#endif
	}
    
    if ([Utility getOSXKernelArch] == OSX_Kernel_Arch_Unsupported)
    {
		LogDebugObjc(@"arch unsupported...\n");
		[self setModuleStatus:PHYSICALMEMORY_STATUS_ERROR_KERNEL_ARCH_UNSUPPORTED];
		[self setModuleEnabled:FALSE];
		return self;
	}
    
    switch ([Utility getOSXVersion])
	{
		case OSX_Version_10_5:
			break;
		case OSX_Version_10_6:
			break;
		case OSX_Version_10_7:
            /* fall through */
        case OSX_Version_Unsupported:
            /* fall through */
        default:
            [self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR_UNSUPPORTED_OS_VERSION];
            [self setModuleEnabled:FALSE];
            return self;
            break;
    }
	
	return self;
}

- (NSString *)moduleStatusString
{
	switch ([self moduleStatus])
	{
		case PHYSICALMEMORY_STATUS_ERROR_OPENING_MEMORY_IMAGE:
			return @"ERROR: UNABLE TO OPEN MEMORY IMAGE FILE";
		case PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_LOAD_KERNEL_EXTENSION:
			return @"ERROR: UNABLE TO LOAD KERNEL EXTENSION";
		case PHYSICALMEMORY_STATUS_WARNING_UNABLE_TO_UNLOAD_KERNEL_EXTENSION:
			return @"WARNING: UNABLE TO UNLOAD KERNEL EXTENSION";
		case PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_OPEN_KERNEL_EXTENSION:
			return @"ERROR: UNABLE TO OPEN KERNEL EXTENSION";
		case PHYSICALMEMORY_STATUS_DISABLED_64_BIT_KERNEL_UNSUPPORTED:
			return @"DISABLED: 64-BIT KERNEL CURRENTLY UNSUPPORTED";
		case PHYSICALMEMORY_STATUS_ERROR_KERNEL_ARCH_UNSUPPORTED:
			return @"ERROR: KERNEL ARCHITECTURE CURRENTLY UNSUPPORTED";
		case PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_BOOT_ARGS:
			return @"ERROR: UNABLE TO READ BOOT ARGUMENTS";
		case PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_EFI_MEMORY_MAP:
			return @"ERROR: UNABLE TO READ EFI MEMORY MAP";
		default:
			return [super moduleStatusString];
	}
}

- (NSString *)memoryImagePath
{
	return [NSString stringWithFormat:@"%@PhysicalMemory.bin", [self moduleCasePath]];
}

- (Boolean)memoryImageOpen
{	
	LiveFile *lf = nil;
	NSString * imagePath = [self memoryImagePath];
	
	// todo enable compression
	lf = [LiveFile allocLiveFileCreate:imagePath withCompression:useCompression];
	[self setMemoryImageLF:lf]; 
	
	if (memoryImageLF == nil)
	{
		[self setModuleStatus: PHYSICALMEMORY_STATUS_ERROR_OPENING_MEMORY_IMAGE];
        [lf release];
		return FALSE;
	}	
	
    [lf release];
	return TRUE;
}

- (Boolean)memoryImageWrite:(UInt64)physicalAddress withPageData:(void *)pageData withLength:(UInt32)length
{
	NSData *data = [NSData dataWithBytesNoCopy:pageData length:length freeWhenDone:FALSE];
	
	if (memoryImageLF == nil) 
	{
		NSLog(@"Failed to open file");
		return FALSE;
	}
	
	[memoryImageLF write:data];
	return TRUE;
}

- (Boolean)memoryImageClose
{
	if (memoryImageLF)
	{
		[memoryImageLF close];
	}
	
	[LiveFile setFileReadOnly:[self memoryImagePath]];
	
	return TRUE;
}

- (BOOL)openKernelExtension
{
	LogDebugObjc(@"Opening kernel extension...\n");
	
	io_iterator_t iterator;
	CFMutableDictionaryRef ref = IOServiceMatching( DRIVER_NAME );
	
	if (!ref)
	{
		LogDebugObjc(@"IOServiceMatching Failed...\n");
		return FALSE;
	}
	
	kern_return_t kernResult = IOServiceGetMatchingServices(kIOMasterPortDefault, ref, &iterator );

	// Make sure the service was located.
    if ( kernResult != KERN_SUCCESS ) 
	{
		// Error.
        LogDebugObjc(@"IOServiceGetMatchingServices returned 0x%08x\n\n", kernResult);

		IOObjectRelease(iterator);
		return FALSE;
    }
	
	// Get the service from the criteria listed above.
    if ( ( kextService = IOIteratorNext( iterator ) ) != IO_OBJECT_NULL ) 
	{
		// Found
		LogDebugObjc( @"Found a device of class %s.\n", DRIVER_NAME );
				
		// Now that the service is located, setup a connection to that service.
		kernResult = IOServiceOpen( kextService, mach_task_self(), 0, &kextConnection );
				
		// Make sure a connection was made.
		if ( kernResult != KERN_SUCCESS ) 
		{
			// Error.
			LogDebugObjc( @"IOServiceOpen returned 0x%08x\n", kernResult );
			IOObjectRelease(iterator);
			return FALSE;
		}
		
		LogDebugObjc( @"Made a connection to class %s.\n", DRIVER_NAME );
		IOObjectRelease(iterator);		
		return TRUE;
	}
		
	LogDebugObjc(@"Failed to find service %s...\n", DRIVER_NAME);
	IOObjectRelease(iterator);	
	return FALSE;
}

- (void)closeKernelExtension
{
	LogDebugObjc(@"Closing kernel extension...\n");
	IOServiceClose(kextConnection);
	LogDebugObjc(@"Kernel extension closed...\n");
	IOObjectRelease(kextConnection);
	IOObjectRelease(kextService);
	LogDebugObjc(@"Kernel objects released...\n");
}

- (void)addDRAMRange:(UInt32)startingPfn withNumPages:(UInt32)numPages
{
	UInt32 i;
	if (dramRangeListCount == 0)
	{
		memset(dramRangeList, 0, sizeof(dramRangeList));
		dramRangeList[dramRangeListCount].pfnRangeStart = startingPfn;
		dramRangeList[dramRangeListCount].pfnRangeEnd = startingPfn + numPages;
		dramRangeListCount++;
		return;
	}
	
	// check to ensure that this region is valid
	for (i = 0; i < dramRangeListCount; i++)
	{
		if (dramRangeList[i].pfnRangeStart == startingPfn)
		{
			LogDebugObjc(@"region already exists... are we re-executing acquisition?\n");
			return;
		}
	}
	
	// index is guaranteed non-zero
	
	// check for colaescing ranges
	if (dramRangeList[dramRangeListCount - 1].pfnRangeEnd == startingPfn)
	{
		// extend range
		dramRangeList[dramRangeListCount - 1].pfnRangeEnd = startingPfn + numPages;
		return;
	} 
	
	// new range
	dramRangeList[dramRangeListCount].pfnRangeStart = startingPfn;
	dramRangeList[dramRangeListCount].pfnRangeEnd = startingPfn + numPages; 
	dramRangeListCount++;
}

- (void)dumpDRAMRanges
{
	unsigned long long startAddr, endAddr;
	uint32_t i;

	for (i = 0; i < dramRangeListCount; i++)
	{
		startAddr = (unsigned long long)dramRangeList[i].pfnRangeStart << 12;
		endAddr = ((unsigned long long)dramRangeList[i].pfnRangeEnd << 12) - 1;
		
		LogDebugObjc(@"DRAM RANGE (%d) - 0x%llx 0x%llx\n", i, startAddr, endAddr);
	}
}

- (void)dumpEfiMemoryRanges:(Boolean)updateDRAMRanges
{
	UInt32 i, memoryRangeCount;
	
	if (!efiMemoryMap)
	{
		LogDebugObjc(@"No EFI memory ranges - getEfiMemoryMap called yet?\n");
		return;
	}
	
	[self xmlInsertStartTag:@"efiMemoryRegions" withLevel:1];
	
	memoryRangeCount = (bootArgs.MemoryMapSize / bootArgs.MemoryMapDescriptorSize);
	
	for (i = 0; i < memoryRangeCount; i++)
	{
		NSString *memoryRangeName = @"";
		EfiMemoryRange *rangeItem = (EfiMemoryRange *)((unsigned char *)efiMemoryMap + bootArgs.MemoryMapDescriptorSize * i);
		UInt32 startingPfn = (UInt32)(rangeItem->PhysicalStart >> 12);
		unsigned long long baseAddress = rangeItem->PhysicalStart;
		unsigned long long numPages = rangeItem->NumberOfPages;
		unsigned long long endAddress = rangeItem->PhysicalStart + numPages * MACRESPONSE_PAGESIZE - 1;
		
		// shouldn't happen... but just make sure
		if (endAddress < baseAddress)
		{
			endAddress = baseAddress;
		}
		
		if (endAddress > topPhysicalAddress)
		{
			topPhysicalAddress = endAddress;
		}
		
		boolean_t rangeIsDram = FALSE;
		
		switch (rangeItem->Type)
		{				
				// any kind of dram
			case kEfiLoaderCode:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiLoaderCode";
				break;				
			case kEfiLoaderData:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiLoaderData";
				break;
			case kEfiBootServicesCode:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiBootServicesCode";
				break;				
			case kEfiBootServicesData:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiBootServicesData";
				break;				
			case kEfiConventionalMemory:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiConventionalMemory";
				break;				
			case kEfiACPIReclaimMemory:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiACPIReclaimMemory";
				break;				
			case kEfiACPIMemoryNVS:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiACPIMemoryNVS";
				break;				
			case kEfiPalCode:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiPalCode";
				break;				
			case kEfiRuntimeServicesCode:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiRuntimeServicesCode";
				break;				
			case kEfiRuntimeServicesData:
				rangeIsDram = TRUE;
				memoryRangeName = @"EfiRuntimeServicesData";
				break;						
				// non dram
			case kEfiReservedMemoryType:
				memoryRangeName = @"EfiReservedMemoryType";
				break;				
			case kEfiUnusableMemory:
				memoryRangeName = @"EfiUnusableMemory";
				break;				
			case kEfiMemoryMappedIO:
				memoryRangeName = @"EfiMemoryMappedIO";
				break;				
			case kEfiMemoryMappedIOPortSpace:
				memoryRangeName = @"EfiMemoryMappedIOPortSpace";
				break;				
				// should never occur
			case kEfiMaxMemoryType:
				memoryRangeName = @"EfiMaxMemoryType";
				break;					
			default:
				// Should never happen...
				memoryRangeName = [NSString stringWithFormat:@"UnkownType-%d", rangeItem->Type];
				break;
		}
		
		//LogDebugObjc(@"%@ - start physical address = 0x%llx number pages = 0x%x\n", memoryRangeName, baseAddress, numPages);
		
		[self xmlInsertStartTag:@"efiMemoryRegion" withLevel:2];
		[self xmlInsertCompleteTag:@"efiMemoryRegionType" withLevel:3 withString:memoryRangeName];
		[self xmlInsertCompleteTag:@"physicalAddressStart" withLevel:3 withString:[NSString stringWithFormat:@"0x%llx", baseAddress]];
		[self xmlInsertCompleteTag:@"physicalAddressEnd" withLevel:3 withString:[NSString stringWithFormat:@"0x%llx", endAddress]];
		
		if (rangeIsDram)
		{
			[self xmlInsertCompleteTag:@"rangeIsDRAM" withLevel:3 withString:@"True"];
		}
		else 
		{
			[self xmlInsertCompleteTag:@"rangeIsDRAM" withLevel:3 withString:@"False"];			
		}

		[self xmlInsertEndTag:@"efiMemoryRegion" withLevel:2];
				
		if (updateDRAMRanges && rangeIsDram)
		{
			[self addDRAMRange:startingPfn withNumPages:(UInt32)numPages];
		}		 
	}	
	
	[self xmlInsertEndTag:@"efiMemoryRegions" withLevel:1];
}

- (Boolean) getBootArgs:(struct boot_args *)bootArgsOut
{
	memset(bootArgsOut, 0, sizeof(struct boot_args));
	
	// if 32-bit kernel architecture, we can get this information from kernel extension
	// if 64-bit kernel architecture, we use dtrace as our workaround
	
	if ([Utility getOSXKernelArch] == OSX_Kernel_Arch_i386)
	{
		size_t outputSize;
		
		outputSize = sizeof(struct boot_args);
		
		if (IOConnectCallStructMethod( kextConnection, kGetKernelBootArgs, NULL, 0, bootArgsOut, &outputSize ) == kIOReturnSuccess)
		{
			return TRUE;
		}
		
		LogDebugObjc(@"Failed to get kernel boot_args from kernel extension (kGetKernelBootArgs)...\n");
		
		// Fall through to try dtrace mechanism
	}
	
	FILE *dtraceStdInOutHandle = NULL;
	unsigned int readIndex = 0;
	char *dtraceArgs[3];
		
	dtraceArgs[0] = "-qn";

	dtraceArgs[1] = "BEGIN \
	{ \
    self->boot_args = ((unsigned char *)(`PE_state).bootArgs); \
    self->i = 0; \
    self->inited = 1; \
	} \
	\
	fbt:::entry \
	/self->inited && self->i < sizeof(struct boot_args)/ \
	{ \
    this->byte = *(self->boot_args + self->i); \
    printf(\"%c\", this->byte); \
    self->i++; \
	} \
	\
	fbt:::return \
	/self->inited && self->i >= sizeof(struct boot_args)/ \
	{ \
    exit(0); \
	}";
	
	dtraceArgs[2] = NULL;
		
	// try dtrace
	if (![Utility executeWithRoot:"/usr/sbin/dtrace" withArgs:dtraceArgs withFilePipe:&dtraceStdInOutHandle])
	{
		LogDebugObjc(@"Failed to execute dtrace script!\n");
		return FALSE;
	}
		
	LogDebugObjc(@"Successfully executed dtrace script!\n");
	
	if (dtraceStdInOutHandle == NULL)
	{
		LogDebugObjc(@"Dtrace execution returned null pipe!\n");
		return FALSE;
	}
	
	while (fread(((char*)&bootArgs) + readIndex, 1, 1, dtraceStdInOutHandle) > 0) 
	{
		readIndex++;
		LogDebugObjc(@"%02x\n", ((char *)&bootArgs)[readIndex - 1]);
		
		if (readIndex >= sizeof(bootArgs)) 
		{
			break;
		}
	}
	
	if (readIndex != sizeof(struct boot_args)) {
		LogDebugObjc(@"Unable to read boot args from pipe (read %d bytes)!\n", (int)readIndex);
		fclose(dtraceStdInOutHandle);
		return FALSE;
	}
		
	LogDebugObjc(@"Read boot args from pipe... %d bytes\n", (int)readIndex);
	fclose(dtraceStdInOutHandle);
	return TRUE;
}

- (void *)mapMemoryRegion:(UInt64)physicalAddress withLength:(UInt64)length
{
	size_t outputSize;
	MemoryAccessIOKit_MapMemoryIn kextIn;
	MemoryAccessIOKit_MapMemoryOut kextOut;
	
	kextIn.physicalAddress = physicalAddress;
	kextIn.requestedLength = length;
	
	memset(&kextOut, 0, sizeof(kextOut));
	
	outputSize = sizeof(kextOut);
	
	if (IOConnectCallStructMethod( kextConnection, kMapMemoryCommand, &kextIn, sizeof(kextIn), &kextOut, &outputSize ) != kIOReturnSuccess)
	{
		LogDebugObjc(@"Failed to map memory via kernel extension (kMapMemoryCommand)...\n");
		return NULL;
	}
	
	LogDebugObjc(@"kextOut: %p 0x%llx 0x%llx\n", (void *)(long)kextOut.mappedVirtualAddress, (long long)kextOut.requestedLength, (long long)kextOut.physicalAddress);
	return (void *)(unsigned long)kextOut.mappedVirtualAddress;
}

- (void)printRange:(void *)buf withLength:(UInt32)length
{
	UInt32 *b32 = (UInt32 *)buf;
	UInt32 i;
	for (i = 0; i < (length/(uint32_t)sizeof(UInt32)); i++)
	{
		LogDebugObjc(@"0x%x: 0x%x 0x%x 0x%x 0x%x\n", (unsigned int)i*4, (unsigned int) b32[i], (unsigned int) b32[i+1], (unsigned int) b32[i+2], (unsigned int) b32[i+3]);
	}
}

- (Boolean) getEfiMemoryMap
{	
	uint32_t memoryMapSize;
	
	memoryMapSize = bootArgs.MemoryMapSize;
	
	LogDebugObjc(@"Obtained boot arguments...\n");
	
	// some quick sanity checks
	
	if (bootArgs.efiMode != 32 && bootArgs.efiMode != 64) 
	{
		LogDebugObjc(@"Invalid bootArgs.efiMode: %d (0x%x)\n", bootArgs.efiMode, bootArgs.efiMode);
		return FALSE;
	}
	
	// since only version 1 has ever seen the light of day...
	if (bootArgs.Version != 1)
	{
		LogDebugObjc(@"Invalid bootArgs.Version: %d (0x%x)\n", bootArgs.Version, bootArgs.Version);
		return FALSE;
	}
	
	LogDebugObjc(@"Validated boot arguments...\n");
	
	LogDebugObjc(@"Allocating %d bytes for MemoryMap...\n", memoryMapSize);
	
	efiMemoryMap = malloc(memoryMapSize);
	
	if (efiMemoryMap == NULL) 
	{
		LogDebugObjc(@"Failed to malloc efiMemoryRangeList...\n");
		return FALSE;
	}
	
	memset(efiMemoryMap, 0, sizeof(efiMemoryMap));
	
	// now fill in memory map
	void *sourceMemoryMap = [self mapMemoryRegion:bootArgs.MemoryMap withLength:memoryMapSize];
	
	if (sourceMemoryMap) 
	{
		LogDebugObjc(@"Obtained memory map successfully...\n");
		memcpy(efiMemoryMap, sourceMemoryMap, memoryMapSize);
		[self printRange:efiMemoryMap withLength:memoryMapSize];
		return TRUE;
	}
	
	LogDebugObjc(@"Failed to obtain memory map...\n");
	return FALSE;
}

/* returns # bytes written */
- (UInt64)fillMemoryHole:(UInt64)startingPhysicalAddress withLength:(UInt64)length
{
	UInt64 endingPhysicalAddress = startingPhysicalAddress + length;
	UInt64 bytesWritten = 0;
	UInt64 addr;
	
	if (length == 0)
	{
		return 0;
	}
	
	unsigned char zeroPage[MACRESPONSE_PAGESIZE];
	
	memset(zeroPage, 0, sizeof(zeroPage));
	
	// fill in missing pages with zeroes
	for (addr = startingPhysicalAddress; addr < endingPhysicalAddress; addr += MACRESPONSE_PAGESIZE) 
	{
		UInt32 bytesLeft = (UInt32)(endingPhysicalAddress - addr);
		
		if (bytesLeft > MACRESPONSE_PAGESIZE) 
		{
			bytesLeft = MACRESPONSE_PAGESIZE;
		}
		
		[self memoryImageWrite:addr withPageData:zeroPage withLength:bytesLeft];		
		bytesWritten += bytesLeft;
	}
	
	return bytesWritten;
}

/* Always writes one page (4KB) of data - startAddress must be aligned to 4K boundary. */
- (Boolean)writeDRAMPage:(UInt64)pageFrameNumber
{
	UInt64 startAddress = pageFrameNumber << 12;
	unsigned char *mappingAddress;
			
/*
	Boolean usedHack = FALSE;
	// special case for address zero... OSX does not let you map address zero, so we start with byte 1
	if (startAddress == 0 || startAddress == 0x100000000ull) 
	{
		usedHack = TRUE;
		startAddress += 1;
		length -= 1;
	}
*/	
	mappingAddress = [self mapMemoryRegion:startAddress withLength:MACRESPONSE_PAGESIZE];		
	
	if (mappingAddress) 
	{
		LogDebugObjc(@"mapped 0x%llx page to %p\n", startAddress, mappingAddress);

/*
		// now we know thanks to x86 page alignment, 
		// we can roll back one byte for these special cases
		if (usedHack) 
		{
			LogDebugObjc(@"hack used and adjusted for...\n");
			startAddress -= 1;
			mappingAddress -= 1;
			length = length + 1;
		}
*/
		//[self printRange:mappingAddress withLength: 64];
		
		[self memoryImageWrite:startAddress withPageData:mappingAddress withLength:MACRESPONSE_PAGESIZE];
		return TRUE;
	} 
	else
	{
		unsigned char zeroPage[MACRESPONSE_PAGESIZE];	
		
		memset(zeroPage, 0, sizeof(zeroPage));
		
		LogDebugObjc(@"[WARNING] Failed to map physical address: 0x%llx\n", startAddress);
		
		[self memoryImageWrite:startAddress withPageData:zeroPage withLength:MACRESPONSE_PAGESIZE];
		return FALSE;
	}
}

- (void)mapDRAMRanges
{
	uint64_t startAddr, endAddr, fileStartAddr, fileEndAddr;
	UInt64 currentAddress = 0, nextPhysicalAddress = 0;
	uint32_t i;
	
	[self memoryImageOpen];
	
	[self xmlInsertStartTag:@"acquisitionImage" withLevel:1];
	
	if (useCompression) 
	{
		[self xmlInsertCompleteTag:@"casePath" withLevel:2 withString:@"./PhysicalMemory/PhysicalMemory.bin.gz"];
		[self xmlInsertCompleteTag:@"imageCompressed" withLevel:2 withString:@"TRUE"];
	} 
	else
	{
		[self xmlInsertCompleteTag:@"casePath" withLevel:2 withString:@"./PhysicalMemory/PhysicalMemory.bin"];
		[self xmlInsertCompleteTag:@"imageCompressed" withLevel:2 withString:@"FALSE"];
	}
	
	[self xmlInsertStartTag:@"acquiredRegions" withLevel:2];

	for (i = 0; i < dramRangeListCount; i++) 
	{
		if ([self cancelAcquisition])
		{	
			break;
		}
		
		NSAutoreleasePool *outerPool = [[NSAutoreleasePool alloc] init];
		
		UInt64 bytesWritten = 0;
		Boolean regionHasUnmappables = FALSE;

		startAddr = (uint64_t)dramRangeList[i].pfnRangeStart << 12;
		endAddr = ((uint64_t)dramRangeList[i].pfnRangeEnd << 12) - 1;
	
		LogDebugObjc(@"Filling holes up to 0x%llx...\n", startAddr);

		bytesWritten = [self fillMemoryHole:nextPhysicalAddress withLength:(startAddr - nextPhysicalAddress)];
		
		LogDebugObjc(@"Wrote 0x%llx bytes of zeros...\n", bytesWritten);

		fileStartAddr = [memoryImageLF offset];
		
		LogDebugObjc(@"MAPPING DRAM RANGE (%d) - 0x%llx 0x%llx\n", i, startAddr, endAddr);
		
		[self xmlInsertStartTag:@"acquiredRegion" withLevel:3];		

		[self xmlInsertCompleteTag:@"physicalAddressStart" withLevel:4 withString:[NSString stringWithFormat:@"0x%llx", startAddr]];
		
		// In a "compressed format" - file offset does not equal physical address
		[self xmlInsertCompleteTag:@"fileOffsetStart" withLevel:4 withString:[NSString stringWithFormat:@"0x%llx", fileStartAddr]];
		
		for (currentAddress = startAddr; currentAddress < endAddr; currentAddress += MACRESPONSE_PAGESIZE)
		{
			if ([self cancelAcquisition])
			{	
				endAddr = currentAddress - 1;
				break;
			}
			
			NSAutoreleasePool *innerPool = [[NSAutoreleasePool alloc] init];

			double percentComplete = (currentAddress * 100.0) / (topPhysicalAddress * 1.0);

			LogDebugObjc(@"physical memory percentComplete %f\n", percentComplete);
			
			[self updateProgress:percentComplete];

			if (![self writeDRAMPage:(currentAddress/MACRESPONSE_PAGESIZE)]) 
			{
				// we have an unmappable region that was written as zeros
				
				if (!regionHasUnmappables) 
				{
					// we need to print the unmappables tag if it doesnt already exist
					[self xmlInsertStartTag:@"unmappablePages" withLevel:4];
				}

				regionHasUnmappables = TRUE;
				[self xmlInsertStartTag:@"unmappablePage" withLevel:5];
				[self xmlInsertCompleteTag:@"physicalAddressStart" withLevel:6 withString:[NSString stringWithFormat:@"0x%llx", currentAddress]];
				[self xmlInsertCompleteTag:@"physicalAddressEnd" withLevel:6 withString:[NSString stringWithFormat:@"0x%llx", currentAddress + MACRESPONSE_PAGESIZE - 1]];
				[self xmlInsertEndTag:@"unmappablePage" withLevel:5];
			}
			
			[innerPool drain];
		}
		
		if (regionHasUnmappables) 
		{
			[self xmlInsertEndTag:@"unmappablePages" withLevel:4];
		}

		// we keep track of this for filling memory holes
		nextPhysicalAddress = endAddr + 1;
		
		fileEndAddr = [memoryImageLF offset] - 1;

		[self xmlInsertCompleteTag:@"physicalAddressEnd" withLevel:4 withString:[NSString stringWithFormat:@"0x%llx", endAddr]];		

		// In a "compressed format" - file offset does not equal physical address
		[self xmlInsertCompleteTag:@"fileOffsetEnd" withLevel:4 withString:[NSString stringWithFormat:@"0x%llx", fileEndAddr]];		

		[self xmlInsertEndTag:@"acquiredRegion" withLevel:3];
		
		[outerPool drain];
	}
	
	[self xmlInsertEndTag:@"acquiredRegions" withLevel:2];
	
	[self memoryImageClose];
	
	if ([self cancelAcquisition])
	{
		[self xmlInsertCompleteTag:@"acquisitionInterrupted" withLevel:2 withString:@"True"];
	}
	else 
	{
		[self xmlInsertCompleteTag:@"acquisitionInterrupted" withLevel:2 withString:@"False"];			
	}


	[self xmlInsertEndTag:@"acquisitionImage" withLevel:1];
	 
	[self setMemoryImageLF: nil];
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	if ([self casePathCreate] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	unsigned long long physMemSize = [[Utility getPhysicalMemorySize] longLongValue];
	unsigned long long freeSpace = [[Utility getFileSystemFreeSpace:[self moduleCasePath]] longLongValue];
	unsigned long long cushion = 2.0 * 1024.0 * 1024.0 * 1024.0;
	
	// If free space is at least 2GB more than the expected physical memory size, continue without prompt
	if ((physMemSize + cushion) > freeSpace)
	{
		LogDebugObjc(@"Unable to retrieve Physical Memory... not enough free space\n");
		
		double physMemSizeGB = (physMemSize * 1.0) / (1024.0) / (1024.0) / (1024.0);
		double cushionGB = (cushion * 1.0) / (1024.0) / (1024.0) / (1024.0);
		double freeSpaceGB = (freeSpace * 1.0) / (1024.0) / (1024.0) / (1024.0);
		
		NSAlert *alert = [[NSAlert alloc] init];
		[alert addButtonWithTitle:@"OK"];
		[alert setMessageText:[NSString stringWithFormat:@"Free Space Needed: %.02fG\nFree Space Available: %.02fG", (physMemSizeGB + cushionGB), freeSpaceGB]];
		[alert setInformativeText:@"Unable to perform Physical Memory Acquisition due to lack of free space available!"];
		[alert setAlertStyle:NSWarningAlertStyle];
		
		[alert runModal];
		[alert release];
		
		[self acquisitionComplete];
		return [self moduleStatus];
	}
	
	// find the path the MemoryAccessIOKit kernel extension
	NSString *kextPath = [[NSBundle mainBundle] bundlePath];

	if ([Utility getOSXKernelArch] == OSX_Kernel_Arch_x86_64)
	{
		kextPath = [NSString stringWithFormat:@"%@%@", kextPath, @"/Contents/Resources/MemoryAccessIOKit.x86_64.kext"];
	}
	else
	{
		kextPath = [NSString stringWithFormat:@"%@%@", kextPath, @"/Contents/Resources/MemoryAccessIOKit.i386.kext"];
	}
	
	// generate random directory in /tmp
	NSString *tempPath = [Utility generateRandomTempDirectory];
	LogDebugObjc(@"Random tempPath: %@\n", tempPath);
	
	NSString *newKextPath = nil;
	
	if ([Utility getOSXKernelArch] == OSX_Kernel_Arch_x86_64)
	{
		newKextPath = [tempPath stringByAppendingFormat:@"MemoryAccessIOKit.x86_64.kext"];
	}
	else
	{
		newKextPath = [tempPath stringByAppendingFormat:@"MemoryAccessIOKit.i386.kext"];
	}
	
	[LiveFile copyDirectory:kextPath toPath:newKextPath withCasePath:nil withCompression:FALSE];
	
	char *args[2];
	args[0] = (char *)[newKextPath UTF8String];
	args[1] = NULL;	
		 
	LogDebugObjc(@"aquireDataToPath! %@\n", outputPath);
	
	if (![Utility executeWithRoot:"/sbin/kextload" withArgs: args withFilePipe:NULL])
	{
		LogDebugObjc(@"kextload error\n");
		[self setModuleStatus:PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_LOAD_KERNEL_EXTENSION];
		return [self moduleStatus];
	}


	sleep(1);

	if (![self openKernelExtension])
	{
		[self setModuleStatus:PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_OPEN_KERNEL_EXTENSION];
		return [self moduleStatus];
	}

	sleep(1);
	
	// get boot arguments to find efi memory map
	if (![self getBootArgs:&bootArgs]) 
	{
		// failed to obtain boot arguments
		[self setModuleStatus:PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_BOOT_ARGS];
		
		// close kernel extesion and unload
		[self closeKernelExtension];
		[Utility executeWithRoot:"/sbin/kextunload" withArgs: args withFilePipe:NULL];
		
		return [self moduleStatus];
	}	
	
	// check if we already have grabbed the memory map (for re-acquisition support)
	if (!efiMemoryMap)
	{
		// read efi memory map
		if (![self getEfiMemoryMap])
		{
			[self setModuleStatus:PHYSICALMEMORY_STATUS_ERROR_UNABLE_TO_READ_EFI_MEMORY_MAP];
			
			// close kernel extesion and unload
			[self closeKernelExtension];
			[Utility executeWithRoot:"/sbin/kextunload" withArgs: args withFilePipe:NULL];
			
			return [self moduleStatus];
		}
				
		[self dumpEfiMemoryRanges:TRUE];
		
	}
	else 
	{
		[self dumpEfiMemoryRanges:FALSE];
	}
	
	[self dumpDRAMRanges];
	
	sleep(1);
	
	[self mapDRAMRanges];
	
	sleep(1);
	
	[self closeKernelExtension];

	sleep(1);
	
	if (![Utility executeWithRoot:"/sbin/kextunload" withArgs: args withFilePipe:NULL])
	{
		LogDebugObjc(@"kextunload error\n");
		[self setModuleStatus:PHYSICALMEMORY_STATUS_WARNING_UNABLE_TO_UNLOAD_KERNEL_EXTENSION];
		return [self moduleStatus];
	}
	
	[self acquisitionComplete];
	
	//LogDebugObjc(@"kextunload: return %d (%d - %s)\n", retVal, errno, strerror(errno));
	
	if ([self cancelAcquisition])
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ACQUISITION_CANCELLED];
		return [self moduleStatus];
	}
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end
