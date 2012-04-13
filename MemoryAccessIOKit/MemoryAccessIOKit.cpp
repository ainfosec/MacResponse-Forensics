/*
 
 MacResponse: Incident Response Toolkit for Mac OS X
 
 MemoryAccessIOKit Kernel Extension
 
 Copyright (C) 2011 - Assured Information Security, Inc. All rights reserved.
 Christopher Patterson <pattersonc.dev _at_ gmail.com>
 
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

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/fcntl.h>

#include <IOKit/IOLib.h>
#include <vm/pmap.h>

#include "MemoryAccessIOKit.h"

/*
 
// #if defined(__i386__) || defined(__x86_64__) __LP64__
 
Memory range descriptor.

typedef struct EfiMemoryRange {
    uint32_t Type;
    uint32_t Pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EfiMemoryRange;

 uint32_t    MemoryMap; 
 uint32_t    MemoryMapSize;
 uint32_t    MemoryMapDescriptorSize;
 uint32_t    MemoryMapDescriptorVersion;
 
 Memory Type Usage before ExitBootServices()
 Mnemonic	 Description
 EfiReservedMemoryType	 Not used.
 EfiLoaderCode	 The code portions of a loaded application. (Note that UEFI OS loaders are UEFI applications.)
 EfiLoaderData	 The data portions of a loaded application and the default data allocation type used by an application to allocate pool memory.
 EfiBootServicesCode	 The code portions of a loaded Boot Services Driver.
 EfiBootServicesData	 The data portions of a loaded Boot Serves Driver, and the default data allocation type used by a Boot Services Driver to allocate pool memory.
 EfiRuntimeServicesCode	 The code portions of a loaded Runtime Services Driver.
 EfiRuntimeServicesData	 The data portions of a loaded Runtime Services Driver and the default data allocation type used by a Runtime Services Driver to allocate pool memory.
 EfiConventionalMemory	 Free (unallocated) memory.
 EfiUnusableMemory	 Memory in which errors have been detected.
 EfiACPIReclaimMemory	 Memory that holds the ACPI tables.
 EfiACPIMemoryNVS	 Address space reserved for use by the firmware.
 EfiMemoryMappedIO	 Used by system firmware to request that a memory-mapped IO region be mapped by the OS to a virtual address so it can be accessed by EFI runtime services.
 EfiMemoryMappedIOPortSpace	 System memory-mapped IO region that is used to translate memory cycles to IO cycles by the processor. Note: There is only one region of type EfiMemoryMappedIoPortSpace defined in the architecture for Itanium-based platforms. As a result, there should be one and only one region of type EfiMemoryMappedIoPortSpace in the EFI memory map of an Itanium-based platform.
 EfiPalCode	 Address space reserved by the firmware for code that is part of the processor.
 
 Memory Type Usage after ExitBootServices()
 Mnemonic	 Description
 EfiReservedMemoryType	 Not used.
 EfiLoaderCode	 The Loader and/or OS may use this memory as they see fit. Note: the OS loader that called ExitBootServices() is utilizing one or
 more EfiLoaderCode ranges.
 EfiLoaderData	 The Loader and/or OS may use this memory as they see fit. Note: the OS loader that called ExitBootServices() is utilizing one or
 more EfiLoaderData ranges.
 EfiBootServicesCode	 Memory available for general use.
 EfiBootServicesData	 Memory available for general use.
 EfiRuntimeServicesCode	 The memory in this range is to be preserved by the loader and OS in the working and ACPI S1–S3 states.
 EfiRuntimeServicesData	 The memory in this range is to be preserved by the loader and OS in the working and ACPI S1–S3 states.
 EfiConventionalMemory	 Memory available for general use.
 EfiUnusableMemory	 Memory that contains errors and is not to be used.
 EfiACPIReclaimMemory	 This memory is to be preserved by the loader and OS until ACPI is enabled. Once ACPI is enabled, the memory in this range is available for general use.
 EfiACPIMemoryNVS	 This memory is to be preserved by the loader and OS in the working and ACPI S1–S3 states.
 EfiMemoryMappedIO	 This memory is not used by the OS. All system memory-mapped IO information should come from ACPI tables.
 EfiMemoryMappedIOPortSpace	 This memory is not used by the OS. All system memory-mapped IO port space information should come from ACPI tables.
 EfiPalCode	 This memory is to be preserved by the loader and OS in the working and ACPI S1–S3 states. This memory may also have other attributes that are defined by the processor implementation
*/

// This required macro defines the class's constructors, destructors,
// and several other methods I/O Kit requires.
OSDefineMetaClassAndStructors(com_ainfosec_driver_MemoryAccessIOKit, IOUserClient)

// Define the driver's superclass.
#define super IOUserClient

/*
 
#if 0
static EfiMemoryRange *EfiMemoryRangeList = NULL; // Allocated with IOAlloc()
static uint32_t EfiMemoryRangeListIndex = 0;

static Boolean com_ainfosec_driver_MemoryAccessIOKit::initEfiMemoryRangeList(void)
{
	UInt32 i, numValidMemoryRanges;
	UInt64 physAddr;
	EfiMemoryRange *        mptr;
	UInt32 mcount, msize;
	EfiMemoryRange *efiMap;
	
	IODeviceMemory *ioMem;
	
	boot_args *             args = (boot_args *) PE_state.bootArgs;
	
	if (!args)
	{
		IOLog("initEfiMemoryRangeList: bootArgs is null!\n");
		return FALSE;
	}
	
	if (EfiMemoryRangeList || EfiMemoryRangeListIndex)
	{
		IOLog("initEfiMemoryRangeList: EfiMemoryRangeList already allocated!\n");
		return TRUE;
	}
	
	IOLog("pe state located at %p\n", &PE_state);
	IOLog("boot args located at %p\n", PE_state.bootArgs);
	
	msize = args->MemoryMapDescriptorSize;
	mcount = args->MemoryMapSize / msize;
	
	IOLog("MemoryMap = 0x%x MemoryMapSize = 0x%x MemoryMapDescriptorSize = 0x%x mcount = %d\n", args->MemoryMap, args->MemoryMapSize, args->MemoryMapDescriptorSize, (int)mcount);
	IOLog("xxx = 0x%lx\n", sizeof(EfiMemoryRange));
	
	ioMem = IODeviceMemory::withRange(args->MemoryMap, args->MemoryMapSize);
	
	if (!ioMem) 
	{
		IOLog("failed to get IODeviceMemory for EfiMemoryRange = 0x%x!\n", args->MemoryMap);
		return FALSE;
	}
	
	IOMemoryMap *p = ioMem->map();
	
	if (!p)	
	{
		IOLog("failed to map IOMemoryMap for EfiMemoryRange = 0x%x!\n", args->MemoryMap);
		ioMem->release();
		return FALSE;
	}
	
	physAddr = (uint64_t)p->getPhysicalAddress();
	
	efiMap = mptr = (EfiMemoryRange *)p->getAddress(); // 32bit getVirtualAddress();
	
	IOLog("mapped efi memory ranges 0x%x to %p (phys = 0x%llx)\n", args->MemoryMap, mptr, physAddr);
	
	numValidMemoryRanges = 0;
	
	for (i = 0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize))
	{
		ppnum_t num = (ppnum_t) mptr->NumberOfPages;
		
		if (!num)
			continue;
		
		numValidMemoryRanges++;
	}
	
	IOLog("total = %u - numValid = %u\n", (unsigned) i, (unsigned) numValidMemoryRanges);
	
	EfiMemoryRangeList = (EfiMemoryRange *)IOMalloc(numValidMemoryRanges * sizeof(EfiMemoryRange));
	EfiMemoryRangeListIndex = 0;
	
	IOLog("EfiMemoryRangeList = %p\n", EfiMemoryRangeList);
	
	if (!EfiMemoryRangeList)
	{
		IOLog("failed to allocate EfiMemoryRangeList!\n");
		p->unmap();
		p->release();
		ioMem->release();
		return FALSE;
	}
	
	mptr = efiMap;
	
	for (i = 0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize))
	{
		ppnum_t num = (ppnum_t) mptr->NumberOfPages;
		
		if (!num)
			continue;
		
		memcpy(&EfiMemoryRangeList[EfiMemoryRangeListIndex], mptr, sizeof(EfiMemoryRange));
		EfiMemoryRangeListIndex++;
		
#if 0		
		boolean_t rangeIsDram = FALSE;
		
		switch (mptr->Type)
		{				
				// any kind of dram
			case kEfiLoaderCode:
				rangeIsDram = TRUE;
				IOLog("kEfiLoaderCode - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiLoaderData:
				rangeIsDram = TRUE;
				IOLog("kEfiLoaderData - base = 0x%x num = 0x%x\n", base, num);
				break;
			case kEfiBootServicesCode:
				rangeIsDram = TRUE;
				IOLog("kEfiBootServicesCode - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiBootServicesData:
				rangeIsDram = TRUE;
				IOLog("kEfiBootServicesData - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiConventionalMemory:
				rangeIsDram = TRUE;
				IOLog("kEfiConventionalMemory - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiACPIReclaimMemory:
				rangeIsDram = TRUE;
				IOLog("kEfiACPIReclaimMemory - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiACPIMemoryNVS:
				rangeIsDram = TRUE;
				IOLog("kEfiACPIMemoryNVS - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiPalCode:
				rangeIsDram = TRUE;
				IOLog("kEfiPalCode - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiRuntimeServicesCode:
				rangeIsDram = TRUE;
				IOLog("kEfiRuntimeServicesCode - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiRuntimeServicesData:
				rangeIsDram = TRUE;
				IOLog("kEfiRuntimeServicesData - base = 0x%x num = 0x%x\n", base, num);
				break;						
				// non dram
			case kEfiReservedMemoryType:
				IOLog("kEfiReservedMemoryType - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiUnusableMemory:
				IOLog("kEfiUnusableMemory - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiMemoryMappedIO:
				IOLog("kEfiMemoryMappedIO - base = 0x%x num = 0x%x\n", base, num);
				break;				
			case kEfiMemoryMappedIOPortSpace:
				IOLog("kEfiMemoryMappedIOPortSpace - base = 0x%x num = 0x%x\n", base, num);
				break;				
				// should never occur
			case kEfiMaxMemoryType:
				IOLog("kEfiMaxMemoryType - base = 0x%x num = 0x%x\n", base, num);
				break;					
			default:
				IOLog("unknown type (%d) - base = 0x%x num = 0x%x\n", mptr->Type, base, num);
				break;
		}
		
		IOSleep(50);
#endif
	}	
	p->unmap();
	ioMem->release();
	p->release();
	return TRUE;
}

static void com_ainfosec_driver_MemoryAccessIOKit::freeEfiMemoryRangeList(void)
{
	if (EfiMemoryRangeList)
	{
		IOFree(EfiMemoryRangeList, sizeof(EfiMemoryRange) * EfiMemoryRangeListIndex);
	}
	
	EfiMemoryRangeListIndex = 0;
	
	EfiMemoryRangeList = NULL;
}
 
IOReturn com_ainfosec_driver_MemoryAccessIOKit::getEFIMemoryListItem(UInt32 * dataIn, EfiMemoryRange *memoryRangeItemOut,
																	 uint32_t inputSize, uint32_t *outputSize )
{
	UInt32 listIndex;
	
	if (!outputSize)
	{
		IOLog("getEFIMemoryListItem Error - output size pointer invalid!\n");
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	if (EfiMemoryRangeListIndex == 0 || EfiMemoryRangeList == NULL)
	{
		IOLog("getEFIMemoryListItem - EFI Memory Range List unitialized!\n");
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	// verify inputsize
	if (inputSize != 4)
	{
		IOLog("getEFIMemoryListItem Error - invalid input size = 0x%x - should be 0x0\n", (int)inputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}	
	
	listIndex = *dataIn;
	
	if (listIndex >= EfiMemoryRangeListIndex)
	{
		IOLog("getEFIMemoryListItem Error - requested bad index = 0x%x!\n", (int) listIndex);
		*outputSize = 0;
		return kIOReturnBadArgument;	
	}
	
	if (*outputSize != sizeof(EfiMemoryRange))
	{
		IOLog("getEFIMemoryListItem Error - invalid output size = 0x%x - should be 0x%x\n", (int)*outputSize, (int)sizeof(EfiMemoryRange));
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	memcpy(memoryRangeItemOut, &EfiMemoryRangeList[listIndex], sizeof(EfiMemoryRange));
	*outputSize = sizeof(EfiMemoryRange);
	
	return( kIOReturnSuccess );
}

IOReturn com_ainfosec_driver_MemoryAccessIOKit::getEFIMemoryListSize(UInt32 * dataIn, UInt32 *memoryListSizeOut,
																	 uint32_t inputSize, uint32_t *outputSize )
{
	UInt32 listSize = sizeof(EfiMemoryRange) * EfiMemoryRangeListIndex;
	
	if (!outputSize)
	{
		IOLog("getEFIMemoryListSize Error - output size pointer invalid!\n");
		return kIOReturnBadArgument;
	}
	
	// verify inputsize
	if (inputSize != 0)
	{
		IOLog("getEFIMemoryListSize Error - invalid input size = 0x%x - should be 0x0\n", (int)inputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	if (*outputSize != 4)
	{
		IOLog("getEFIMemoryListSize Error - invalid output size = 0x%llx - should be 0x4\n", (long long) *outputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	*memoryListSizeOut = listSize;
	*outputSize = 4;
	
	return( kIOReturnSuccess );
}

//
// Maps requested page frame and copies page to outputPage buffer.
// outputPage buffer must be at least 4096 bytes (4KB).
//
// Returns TRUE if page was successfully mapped and copied, FALSE otherwise.
//
Boolean com_ainfosec_driver_MemoryAccessIOKit::readMemoryPage(UInt32 requestedPfn, UInt8 *outputPage)
{
	UInt8 *mappedPage;
	UInt64 physAddr;
	IODeviceMemory *ioMem;
	
	UInt64 startAddr = requestedPfn * 4096;

	// can't use address 0 for starting address of IODeviceMemory::withRange
	if (startAddr == 0)	
	{
		IOLog("page 0 .. starting with 1\n");
		ioMem = IODeviceMemory::withRange(1, 4095);
	} 
	else if (startAddr == 0x100000000ULL)
	{
		UInt64 next = 0x100000001ULL; // avoids a compiler warning
		IOLog("page 0x100000 .. starting with 0x%llx\n", next);
		ioMem = IODeviceMemory::withRange(next, 4095);	
	}
	else
	{
		IOLog("requesting range 0x%llx\n", startAddr);
		ioMem = IODeviceMemory::withRange(startAddr, 4096);
	}
	
	if (!ioMem) 
	{
		IOLog("failed to get IODeviceMemory for pfn = 0x%x!\n", (unsigned int)requestedPfn);
		return FALSE;
	}

	IOMemoryMap *p = ioMem->map();
	
	if (!p)	
	{
		IOLog("failed to map IOMemoryMap for pfn = 0x%x!\n", (unsigned int)requestedPfn);
		ioMem->release();
		return FALSE;
	}
	
	physAddr = (uint64_t) p->getPhysicalAddress();

	mappedPage = (unsigned char *) p->getAddress(); //getVirtualAddress() is 32bit only
	
	IOLog("mapped page 0x%x to %p (phys = 0x%llx)\n", (unsigned int)requestedPfn, mappedPage, (unsigned long long)physAddr);
	
	if (!mappedPage)
	{
		IOLog("failed to getAddress() for pfn = 0x%x\n", (unsigned int)requestedPfn);
		return FALSE;
	}
	
	// check exception case for memory page 0 // 4GB mapping
	if (startAddr == 0 || startAddr == 0x100000000ULL) 
	{
		outputPage[0] = 0;
		memcpy(outputPage+1, mappedPage, 4095);
	} 
	else
	{
		memcpy(outputPage, mappedPage, 4096);
	}		
	
	p->unmap();
	ioMem->release();
	p->release();
	
	return TRUE;
}
 
 
#endif // 0
*/

/**
 * Free descriptors for process page mapping created in mapMemoryIntoUserTask().
 */ 
void com_ainfosec_driver_MemoryAccessIOKit::freeMemoryDescriptors(void)
{
	if (lastMemoryMap)
	{
		IOLog("freeing lastMemoryMap...\n");
		lastMemoryMap->unmap();
		lastMemoryMap->release();
		lastMemoryMap = NULL;
	}
	
	if (lastMemoryDescriptor)
	{
		IOLog("freeing lastMemoryDescriptor...\n");
		lastMemoryDescriptor->release();
		lastMemoryDescriptor = NULL;
	}
}

/**
 * Maps a buffer (requestedAddreess) of length requestedSize into specified userTask.
 * Returns the user task's virtual address for the mapping, otherwise 0.
 */
UInt64 com_ainfosec_driver_MemoryAccessIOKit::mapMemoryIntoUserTask(task_t userTask, UInt64 requestedAddress, UInt64 requestedSize)
{
	// ensure the previous descriptors have been released
	freeMemoryDescriptors();
	
	lastMemoryDescriptor = IOMemoryDescriptor::withPhysicalAddress((IOPhysicalAddress)requestedAddress, (IOByteCount)requestedSize, kIODirectionIn );
	
	if (!lastMemoryDescriptor)
	{
		IOLog("mapMemoryIntoUserTask: unable to allocate memDesc!\n");
		return 0;
	}
	
	lastMemoryMap = lastMemoryDescriptor->createMappingInTask(userTask, 0, kIOMapAnywhere | kIOMapDefaultCache, 0, 0); 
	
	if (!lastMemoryMap)
	{
		IOLog("mapMemoryIntoUserTask: unable to map to user task!\n");
		freeMemoryDescriptors();
		return 0;
	}
	
	return (UInt64) lastMemoryMap->getAddress();	
}

/**
 * kMapMemoryCommand IOCTL
 */
IOReturn com_ainfosec_driver_MemoryAccessIOKit::mapMemory(MemoryAccessIOKit_MapMemoryIn *dataIn, 
														  MemoryAccessIOKit_MapMemoryOut *dataOut,
														  uint32_t inputSize, uint32_t *outputSize )
{
	// verify inputsize
	if (inputSize != sizeof(MemoryAccessIOKit_MapMemoryIn))
	{
		IOLog("getMemoryPage Error - invalid input size = 0x%x - should be 0x4\n", (unsigned int)inputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	if (!outputSize)
	{
		IOLog("getMemoryPage Error - output size pointer invalid!\n");
		return kIOReturnBadArgument;
	}
	
	if (*outputSize != sizeof(MemoryAccessIOKit_MapMemoryOut))
	{
		IOLog("getMemoryPage Error - invalid output size = 0x%x - should be 0x1000\n", (unsigned int)*outputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	memset(dataOut, 0, sizeof(MemoryAccessIOKit_MapMemoryOut));
	
	dataOut->mappedVirtualAddress = mapMemoryIntoUserTask(current_task(), dataIn->physicalAddress, dataIn->requestedLength);

	if (dataOut->mappedVirtualAddress)
	{
		dataOut->physicalAddress = dataIn->physicalAddress;
		dataOut->requestedLength = dataIn->requestedLength;
		
		IOLog("mapping for 0x%llx (len = 0x%llx) created at: 0x%llx\n", 
			  (unsigned long long)dataOut->physicalAddress, 
			  (unsigned long long)dataOut->requestedLength,
			  (unsigned long long)dataOut->mappedVirtualAddress);
	}
	
    return( kIOReturnSuccess );
}

#ifdef __i386__

/**
 * kGetKernelBootArgs IOCTL.
 * 
 * Reads kernel boot args (PE_state.bootArgs) structure for user.  
 * This currently is only reliable for 32-bit kernels,
 * since Apple has restricted access to PE_state variable for x86_64 builds.
 */
IOReturn com_ainfosec_driver_MemoryAccessIOKit::getKernelBootArgs(const void *dataIn, struct boot_args *dataOut,
																  uint32_t inputSize, uint32_t *outputSize)
{	
	if (!outputSize)
	{
		IOLog("getKernelBootArgs Error - output size pointer invalid!\n");
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	// verify inputsize
	if (inputSize != 0)
	{
		IOLog("getKernelBootArgs Error - invalid input size = 0x%x - should be 0x0\n", (int)inputSize);
		*outputSize = 0;
		return kIOReturnBadArgument;
	}	
	
	if (*outputSize != sizeof(struct boot_args))
	{
		IOLog("getKernelBootArgs Error - invalid output size = 0x%x - should be 0x%x\n", (int)*outputSize, (int)sizeof(EfiMemoryRange));
		*outputSize = 0;
		return kIOReturnBadArgument;
	}
	
	memcpy(dataOut, PE_state.bootArgs, sizeof(struct boot_args));
	*outputSize = sizeof(struct boot_args);
	
	return( kIOReturnSuccess );
}

#endif

/**
 * Handle IOCTLs...
 */
IOReturn com_ainfosec_driver_MemoryAccessIOKit::externalMethod(uint32_t selector, 
															   IOExternalMethodArguments *arguments,
															   IOExternalMethodDispatch *dispatch, 
															   OSObject *target, void *reference )
{
	IOReturn err = kIOReturnSuccess;
	
	//IOLog("externalMethod(%d) 0x%x - ouputsize = 0x%x\n", (int)selector, (int)err, arguments->structureOutputSize);
	//IOLog("currentTask = %p, kernel_task = %p\n", current_task(), kernel_task);
	
    switch (selector)
    {
        /*
		case kGetMemoryListSizeCommand:
		{
            err = getEFIMemoryListSize( (UInt32 *) arguments->structureInput, 
									    (UInt32 *)  arguments->structureOutput,
									    arguments->structureInputSize, 
									    &arguments->structureOutputSize );
            break;
		}
        case kGetMemoryListItemCommand:
		{
            err = getEFIMemoryListItem( (UInt32 *) arguments->structureInput, 
									    (EfiMemoryRange *)  arguments->structureOutput,
									    arguments->structureInputSize, 
										&arguments->structureOutputSize );
            break;
		}	
        */
		case kMapMemoryCommand:
		{
            err = mapMemory( (MemoryAccessIOKit_MapMemoryIn *) arguments->structureInput, 
							 (MemoryAccessIOKit_MapMemoryOut *)  arguments->structureOutput,
							 arguments->structureInputSize, 
							 &arguments->structureOutputSize );
            break;
		}
#ifdef __i386__
		case kGetKernelBootArgs:
		{
            err = getKernelBootArgs( arguments->structureInput, 
									 (struct boot_args *)  arguments->structureOutput,
									 arguments->structureInputSize, 
									 &arguments->structureOutputSize );
            break;
		}
#endif
        default:
		{
            err = kIOReturnBadArgument;
            break;
		}
    }
	
	//return super::externalMethod( selector, arguments, dispatch, target, reference );
    return (err);
}

bool com_ainfosec_driver_MemoryAccessIOKit::init(OSDictionary *dict)
{
    bool result = super::init(dict);
	
    IOLog("MacResponse Live Kext (MemoryAccessIOKit) initializing...\n");
	
	lastMemoryDescriptor = NULL;
	lastMemoryMap = NULL;
	
    return result;
}

void com_ainfosec_driver_MemoryAccessIOKit::free(void)
{
    IOLog("MacResponse Live Kext (MemoryAccessIOKit)  freeing...\n");
		
	// ensure any outstanding descriptors are freed
	freeMemoryDescriptors();
	
	super::free();
}

bool com_ainfosec_driver_MemoryAccessIOKit::start(IOService *provider)
{
    bool result = super::start(provider);

    IOLog("MacResponse Live Kext (MemoryAccessIOKit)  starting...\n");
	
	if (result) 
	{        
        registerService();
    }

	//initEfiMemoryRangeList();
	
    return result;
}

void com_ainfosec_driver_MemoryAccessIOKit::stop(IOService *provider)
{
    IOLog("MacResponse Live Kext (MemoryAccessIOKit)  stopping...\n");
	
	//freeEfiMemoryRangeList();
	
	// ensure any outstanding descriptors are freed
	freeMemoryDescriptors();
	
    super::stop(provider);
}

