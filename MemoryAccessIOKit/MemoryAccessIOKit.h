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


#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOUserClient.h>

#define MEMORYACCESSIOKIT_SELECTOR 1

#include "kext_shared.h"

class com_ainfosec_driver_MemoryAccessIOKit : public IOUserClient
{
	OSDeclareDefaultStructors(com_ainfosec_driver_MemoryAccessIOKit)
	
public:
    virtual bool init(OSDictionary *dictionary = 0);
    virtual void free(void);
    virtual bool start(IOService *provider);
    virtual void stop(IOService *provider);

private:
	//virtual Boolean readMemoryPage(UInt32 pfn, UInt8 *buf);

#ifdef __i386__
	virtual IOReturn getKernelBootArgs(const void *dataIn, 
									   struct boot_args *dataOut,
									   uint32_t inputSize,
									   uint32_t *outputSize);
	
	//virtual IOReturn getEFIMemoryListSize(UInt32 *dataIn, UInt32 *memoryListSizeOut, uint32_t inputSize, uint32_t *outputSize );
	//virtual IOReturn getEFIMemoryListItem(UInt32 *dataIn, EfiMemoryRangeItem *memoryRangeItemOut, uint32_t inputSize, uint32_t *outputSize );
#endif
	
	virtual IOReturn mapMemory(MemoryAccessIOKit_MapMemoryIn *dataIn, 
							   MemoryAccessIOKit_MapMemoryOut *dataOut, 
							   uint32_t inputSize,
							   uint32_t *outputSize );
	
	virtual void freeMemoryDescriptors(void);
	
	virtual UInt64 mapMemoryIntoUserTask(task_t userTask,
										 UInt64 requestedAddress,
										 UInt64 requestedSize);
	
	virtual IOReturn externalMethod(uint32_t selector, 
									IOExternalMethodArguments *arguments, 
									IOExternalMethodDispatch *dispatch, 
									OSObject *target, void *reference );

	/**
	 * Client application will individually request pages.  
	 * Client should never have any outstanding open memory descriptors, and we will 
	 * forcefully unmap whenever a new request is made (which allows us to 
	 * not require MacResponse Live app to signal when its finished with a buffer).
	 *
	 * NOTE: This approach does not support multiple outstanding requests (or threads requesting/reading memory simultaneously).
	 * A potentially better approach would be to record a list of outstanding requests and have the caller release them.
	 */
	IOMemoryDescriptor *lastMemoryDescriptor; // We only allow one outstanding allocation at any given time.
	IOMemoryMap *lastMemoryMap;
};