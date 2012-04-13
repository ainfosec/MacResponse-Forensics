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

#include <sys/sysctl.h>

#import "SystemControl.h"
#import "CaseLog.h"

// data structure to hold all relevant information pertaining to
// system control items that we may want to reference
struct list {
	char *name;
	struct ctlname *list;
	int size;
	int index;
};

// arrays defined in sysctl.h
struct ctlname kernname[] = CTL_KERN_NAMES;
struct ctlname vmname[] = CTL_VM_NAMES;
struct ctlname hwname[] = CTL_HW_NAMES;
struct ctlname username[] = CTL_USER_NAMES;

int namesInList = 4;
struct list namelist[4] = { {"kern", kernname, KERN_MAXID, CTL_KERN},
                            {"vm", vmname, VM_MAXID, CTL_VM},
                            {"hw", hwname, HW_MAXID, CTL_HW},
                            {"user", username, USER_MAXID, CTL_USER} };

@implementation SystemControl

- (id)init
{
	[super init];
	[self setModuleName: @"System Information"];
	[self setModuleShortName:@"SystemInformation"];
	[self setModuleEnabled: TRUE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	
	return self;
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"systemControlItems" withLevel:1];
	
	int i, j;
	char buffer[BUFSIZ];
    //for each name (ie, kern, vm, hw, or user)
	for (i = 0; i < namesInList; i++)
	{
		LogDebugObjc(@"Name: %s\n", namelist[i].name);
		
		for (j = 1; j < namelist[i].size; j++)
		{
			[self xmlInsertStartTag:@"systemControlItem" withLevel:2];
			
            // get the type of data
			int type = namelist[i].list[j].ctl_type;
			
			// There are 5 types of data that we may encounter
			//   CTLTYPE_INT/STRING/QUAD are simple data types that can be printed as is
			//   CTLTYPE_NODE/OPAQUE are complex data types that require specific parsing
			//                       if we would like to print them.  
			if ((type == CTLTYPE_INT) || (type == CTLTYPE_STRING) || (type == CTLTYPE_QUAD))
			{
                // create mib (management information base) to let sysctl know what data to collect
                // here we are simply passing in the index to which set of data we want, and the index
                //  into that set to get the relevant information
                //
                // for example {CTL_KERN, 2} gets the item at index 2 for the CTL_KERN data set
				int mib[2] = {namelist[i].index, j};
				size_t size = BUFSIZ;
				sysctl(mib, 2, buffer, &size, NULL, 0);
				
                // store the data set and data item names (ie, kern.ostype)
				[self xmlInsertCompleteTag:@"sysctlName" withLevel:3 withString:[NSString stringWithFormat:@"%s.%s", namelist[i].name, namelist[i].list[j].ctl_name]];
																		  
                // store the values according to their data types
				if (type == CTLTYPE_INT)
				{
					LogDebugObjc(@"%s.%s = %u\n", namelist[i].name, namelist[i].list[j].ctl_name, *(int *)buffer);
					[self xmlInsertCompleteTag:@"sysctlValue" withLevel:3 withString:[NSString stringWithFormat:@"%u", *(int *)buffer]];
				}
				else if (type == CTLTYPE_STRING)
				{
					LogDebugObjc(@"%s.%s = %s\n", namelist[i].name, namelist[i].list[j].ctl_name, buffer);
					[self xmlInsertCompleteTag:@"sysctlValue" withLevel:3 withString:[NSString stringWithFormat:@"%s", buffer]];
				}
				else if (type == CTLTYPE_QUAD)
				{
					LogDebugObjc(@"%s.%s = %qd\n", namelist[i].name, namelist[i].list[j].ctl_name, *(quad_t *)buffer);
					[self xmlInsertCompleteTag:@"sysctlValue" withLevel:3 withString:[NSString stringWithFormat:@"%qd", *(quad_t *)buffer]];
				}
			}
			// for now, we are printing the type to at least show that this data exists
			//
			// if any of these data types are identified as relevant, then we will need to 
			// build a specific parser function (if not create a new module) to handle it
			else if (type == CTLTYPE_NODE)
			{
				[self xmlInsertCompleteTag:@"sysctlName" withLevel:3 withString:[NSString stringWithFormat:@"%s.%s", namelist[i].name, namelist[i].list[j].ctl_name]];
				[self xmlInsertCompleteTag:@"sysctlValue" withLevel:3 withString:@"CTLTYPE_NODE"];
			}
			else if (type == CTLTYPE_OPAQUE)
			{
				[self xmlInsertCompleteTag:@"sysctlName" withLevel:3 withString:[NSString stringWithFormat:@"%s.%s", namelist[i].name, namelist[i].list[j].ctl_name]];
				[self xmlInsertCompleteTag:@"sysctlValue" withLevel:3 withString:@"CTLTYPE_OPAQUE"];
			}
			
			[self xmlInsertEndTag:@"systemControlItem" withLevel:2];
		}
	}
	
	[self xmlInsertEndTag:@"systemControlItems" withLevel:1];
	
	// now go retrieve the following config files if they exist
	//   /etc/passwd
	//   /etc/group
	//   /etc/fstab
	//   /etc/hosts
	//   /etc/hosts.allow
	
	if ([self casePathCreate] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"systemConfigFiles" withLevel:1];
	
	// List of config files to look for
	NSArray *configFiles = [NSArray arrayWithObjects:@"passwd", @"group", @"fstab", @"hosts", @"hosts.allow", nil];
	NSString *baseConfigPath = @"/etc";
	
	for (NSString *configFile in configFiles)
	{
		NSString *path = [baseConfigPath stringByAppendingPathComponent:configFile];
		LogDebugObjc(@"Attempting to copy file: %@\n", path);
		
		BOOL isDir;
        // if the file exists, go get it
		if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] && !isDir)
		{
			NSString *newPath = [[self moduleCasePath] stringByAppendingPathComponent:configFile];
			[LiveFile copyFile:path toPath:newPath withCompression:useCompression];
			[LiveFile setFileReadOnly:newPath];
			
            [self xmlInsertStartTag:@"systemConfigFile" withLevel:2];
			[self xmlInsertCompleteTag:@"filePath" withLevel:3 withString:path];
            [self xmlInsertEndTag:@"systemConfigFile" withLevel:2];
		}
	}
	
	[self xmlInsertEndTag:@"systemConfigFiles" withLevel:1];
	
	[self xmlInsertStartTag:@"systemStartupItems" withLevel:1];
	
	// also look for startup items and get them if there are any
	NSArray *startupItemLocations = [NSArray arrayWithObjects:@"/Library/StartupItems", @"/System/Library/StartupItems", nil];
	
	for (NSString *location in startupItemLocations)
	{
		LogDebugObjc(@"Getting startup items located in: %@\n", location);
		
		NSFileManager *fm = [NSFileManager defaultManager];			
		NSArray *files = [fm contentsOfDirectoryAtPath:location error:NULL];
		
		for(NSString *file in files)
		{
			BOOL isDir;
			NSString *startupPath = [location stringByAppendingPathComponent:file];
			if ([fm fileExistsAtPath:startupPath isDirectory:&isDir] && isDir)
			{
				LogDebugObjc(@"Attempting to copy startup item: %@\n", startupPath);
				NSString *newStartupPath = [[self moduleCasePath] stringByAppendingPathComponent:file];
				[LiveFile copyDirectory:startupPath toPath:newStartupPath withCasePath:nil withCompression:useCompression];
				
                [self xmlInsertStartTag:@"systemStartupItem" withLevel:2];
                [self xmlInsertCompleteTag:@"filePath" withLevel:3 withString:startupPath];
                [self xmlInsertEndTag:@"systemStartupItem" withLevel:2];
			}
		}
	}
	
	[self xmlInsertEndTag:@"systemStartupItems" withLevel:1];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end