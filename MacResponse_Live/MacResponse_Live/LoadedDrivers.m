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

#import "LoadedDrivers.h"
#import "CaseLog.h"
#import <mach-o/arch.h>
#import <mach/mach.h>

extern const NXArchInfo *OSKextGetRunningKernelArchitecture(void);
extern CFArrayRef OSKextCreateLoadedKextInfo(CFMutableArrayRef);

@implementation LoadedDrivers

- (id)init
{
	[super init];
	[self setModuleName: @"Driver Information"];
	[self setModuleShortName:@"DriverInformation"];
	[self setModuleEnabled: TRUE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	
	return self;
}

- (NSString *)moduleStatusString
{
	switch ([self moduleStatus])
	{
		case DRIVERINFORMATION_STATUS_ERROR_RETRIEVING_DRIVER_INFORMATION:
			return @"ERROR: UNABLE TO RETRIEVE DRIVER INFORMATION";
		default:
			return [super moduleStatusString];
	}
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	Boolean retVal = FALSE;
	
	switch ([Utility getOSXVersion])
	{
		case OSX_Version_10_5:
			retVal = [self getLoadedDrivers10_5];
			break;
		case OSX_Version_10_6:
			retVal = [self getLoadedDrivers10_6];
			break;
		case OSX_Version_10_7:
			// the code to get Loaded Drivers built for OSX 10.6 works for 10.7
            retVal = [self getLoadedDrivers10_6];
			break;
		case OSX_Version_Unsupported:
			LogDebugObjc(@"Running on unsupported version of OS X\n");
			[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR_UNSUPPORTED_OS_VERSION];
			retVal = FALSE;
			break;
		default:
			// shouldn't get this
			[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
			retVal = FALSE;
			break;
	}
	
	if (!retVal)
	{
		[self xmlClose];
		return [self moduleStatus];
	}
	 
	[self acquisitionComplete];
	
	return [self moduleStatus];
}

- (Boolean)getLoadedDrivers10_6
{
	LogDebugObjc(@"Running 10.6\n");
    
    // for OSX 10.6 and 10.7 kmod_get_info no longer returns the driver information that we
    // are interested in
	
	CFMutableArrayRef bundleIDs;
	
    // create an empty mutable array of Bundle IDs to be used later for 
    // loading kernel extension information
	bundleIDs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
	if (!bundleIDs)
	{
		LogDebugObjc(@"Error\n");
		[self setModuleStatus:DRIVERINFORMATION_STATUS_ERROR_RETRIEVING_DRIVER_INFORMATION];
		return FALSE;
	}
	
    // load the kernel extension information into an array of dictionaries
	CFArrayRef loadedKextInfo = OSKextCreateLoadedKextInfo(bundleIDs);
	
	CFIndex count = CFArrayGetCount(loadedKextInfo);
	LogDebugObjc(@"Count: %d\n", count);
	
	[self xmlInsertStartTag:@"drivers" withLevel:1];
	
	long i;
	for (i = 0; i < count; i++)
	{
		[self xmlInsertStartTag:@"driver" withLevel:2];
		
        // retrieve the dictionary for each item in the array
		CFDictionaryRef	kextInfo = (CFDictionaryRef)CFArrayGetValueAtIndex(loadedKextInfo, i);
        
        // for each item, use CFDictionaryGetValue to pull the relevant information
        // out of the dictionary
        //
        // the items we are currently interest in collected are:
        //  OSBundleLoadTag
        //  OSBundleRetainCount
        //  OSBundleLoadAddress
        //  OSBundleLoadSize
        //  CFBundleIdentifier
        //  CFBundleVersion
        //  OSBundleDependencies
        //      OSBundleDependencies returns an array of driver indexes that
        //      the current driver references
		
		CFNumberRef loadTag = (CFNumberRef)CFDictionaryGetValue(kextInfo, CFSTR("OSBundleLoadTag"));
		LogDebugObjc(@"Index: %@\n", loadTag);
		[self xmlInsertCompleteTag:@"driverIndex" withLevel:3 withString:[NSString stringWithFormat:@"%@", loadTag]];
		
		CFNumberRef retainCount = (CFNumberRef)CFDictionaryGetValue(kextInfo, CFSTR("OSBundleRetainCount"));
		LogDebugObjc(@"Retain Count: %@\n", retainCount);
		[self xmlInsertCompleteTag:@"driverRefs" withLevel:3 withString:[NSString stringWithFormat:@"%@", retainCount]];
		
		CFNumberRef loadAddress = (CFNumberRef)CFDictionaryGetValue(kextInfo, CFSTR("OSBundleLoadAddress"));
		LogDebugObjc(@"Load Address: %@\n", loadAddress);
		uint64_t loadAddressValue;
		CFNumberGetValue(loadAddress, kCFNumberSInt64Type, &loadAddressValue);
		[self xmlInsertCompleteTag:@"driverAddress" withLevel:3 withString:[NSString stringWithFormat:@"%#x", loadAddressValue]];
		
		CFNumberRef loadSize = (CFNumberRef)CFDictionaryGetValue(kextInfo, CFSTR("OSBundleLoadSize"));
		LogDebugObjc(@"Load Size: %@\n", loadSize);
		uint32_t loadSizeValue;
		CFNumberGetValue(loadSize, kCFNumberSInt32Type, &loadSizeValue);
		[self xmlInsertCompleteTag:@"driverSize" withLevel:3 withString:[NSString stringWithFormat:@"%#x", loadSizeValue]];
		
		CFStringRef bundleID = (CFStringRef)CFDictionaryGetValue(kextInfo, CFSTR("CFBundleIdentifier"));
		LogDebugObjc(@"Bundle ID: %@\n", bundleID);
		[self xmlInsertCompleteTag:@"driverName" withLevel:3 withString:[NSString stringWithFormat:@"%@", bundleID]];
		
		CFStringRef bundleVersion = (CFStringRef)CFDictionaryGetValue(kextInfo, CFSTR("CFBundleVersion"));
		LogDebugObjc(@"Version: %@\n", bundleVersion);
		[self xmlInsertCompleteTag:@"driverVersion" withLevel:3 withString:[NSString stringWithFormat:@"%@", bundleVersion]];
		
		CFArrayRef dependencyTags = (CFArrayRef)CFDictionaryGetValue(kextInfo, CFSTR("OSBundleDependencies"));
		if (dependencyTags && CFArrayGetCount(dependencyTags))
		{
			CFIndex depCount = CFArrayGetCount(dependencyTags);
			if (depCount > 0)
			{
				[self xmlInsertStartTag:@"dependencies" withLevel:3];
				long j;
				for (j = 0; j < depCount; j++)
				{
					CFNumberRef depTag = (CFNumberRef)CFArrayGetValueAtIndex(dependencyTags, j);
					LogDebugObjc(@"Dependency: %@\n", depTag);
					[self xmlInsertStartTag:@"dependency" withLevel:4];
					[self xmlInsertCompleteTag:@"driverIndex" withLevel:5 withString:[NSString stringWithFormat:@"%@", depTag]];
					[self xmlInsertEndTag:@"dependency" withLevel:4];
				}
				[self xmlInsertEndTag:@"dependencies" withLevel:3];
			}
		}
		
		[self xmlInsertEndTag:@"driver" withLevel:2];
	}
	
	[self xmlInsertEndTag:@"drivers" withLevel:1];
	
	if (loadedKextInfo)
	{
		CFRelease(loadedKextInfo);
	}
	
	if (bundleIDs)
	{
		CFRelease(bundleIDs);
	}
	return TRUE;
}

- (Boolean)getLoadedDrivers10_5
{
	LogDebugObjc(@"Running 10.5\n");
	
	kern_return_t kReturn;
	kmod_info_32_v1_t *kmodInfo = NULL;
	mach_msg_type_number_t kmodBytes = 0;
	int kmodCount = 0;
	mach_port_t	host_port = mach_host_self();
	
	[self xmlInsertStartTag:@"drivers" withLevel:1];
	
	LogDebugObjc(@"Getting kernel mod info\n");
	kReturn = kmod_get_info(host_port, (void *)&kmodInfo, &kmodBytes);

	if (kReturn != KERN_SUCCESS)
	{
		LogDebugObjc(@"Error getting kmod info (%d)\n", kReturn);
		[self setModuleStatus:DRIVERINFORMATION_STATUS_ERROR_RETRIEVING_DRIVER_INFORMATION];
		return FALSE;
	}
    
    // kmod_info_32_v1_t is a compatibility definition of kmod_info_t for 32-bit kernel extensions
    // the information from this data structure we are currently interested in is:
    //      uint32_t    id                      ** Driver Index
    //      int32_t     reference_count         ** Reference Count
    //      uint32_t    address                 ** Driver Address
    //      uint32_t    size                    ** Driver Size
    //      uint8_t     name[KMOD_MAX_NAME]     ** Driver Name
    //      uint8_t     version[KMOD_MAX_NAME]  ** Driver Verions
    //
    // more information on this data structure and additional items we may want to
    // consider collecting in the future can be found in kmod.h
	kmod_info_32_v1_t *kmodPtr;
	for (kmodPtr = (kmod_info_32_v1_t *)kmodInfo; kmodPtr->next_addr; kmodPtr++, kmodCount++)
	{
		[self xmlInsertStartTag:@"driver" withLevel:2];
		
		LogDebugObjc(@"Driver ID: %d\n", kmodPtr->id);
		[self xmlInsertCompleteTag:@"driverIndex" withLevel:3 withString:[NSString stringWithFormat:@"%d", kmodPtr->id]];
		
		LogDebugObjc(@"Driver Ref Count: %d\n", kmodPtr->reference_count);
		[self xmlInsertCompleteTag:@"driverRefs" withLevel:3 withString:[NSString stringWithFormat:@"%d", kmodPtr->reference_count]];
		
		LogDebugObjc(@"Driver Address: %#x\n", kmodPtr->address);
		[self xmlInsertCompleteTag:@"driverAddress" withLevel:3 withString:[NSString stringWithFormat:@"%#x", kmodPtr->address]];
		
		LogDebugObjc(@"Driver Size: %#x\n", kmodPtr->size);
		[self xmlInsertCompleteTag:@"driverSize" withLevel:3 withString:[NSString stringWithFormat:@"%#x", kmodPtr->size]];
		
		LogDebugObjc(@"Driver Name: %s\n", kmodPtr->name);
		[self xmlInsertCompleteTag:@"driverName" withLevel:3 withString:[NSString stringWithFormat:@"%s", kmodPtr->name]];
		
		LogDebugObjc(@"Driver Version: %s\n", kmodPtr->version);
		[self xmlInsertCompleteTag:@"driverVersion" withLevel:3 withString:[NSString stringWithFormat:@"%s", kmodPtr->version]];
		
		[self xmlInsertEndTag:@"driver" withLevel:2];
	}
	
	LogDebugObjc(@"Kernel Mod Count: %d\n", kmodCount);

	mach_port_deallocate(mach_task_self(), host_port);
	vm_deallocate(mach_task_self(), (vm_address_t)kmodInfo, kmodBytes);
	
	[self xmlInsertEndTag:@"drivers" withLevel:1];
	
	return TRUE;
}

@end
