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

#import "PropertyLists.h"
#import "CaseLog.h"

#include <CommonCrypto/CommonDigest.h>

@implementation PropertyLists

- (id)init
{
	[super init];
	[self setModuleName: @"Property Lists"];
	[self setModuleShortName:@"PropertyLists"];
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
	
	if ([self casePathCreate] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"propertyLists" withLevel:1];
	
	// List of directories to look in for Property List (plist) files
    // These are two common places to find Property List files that hold
    // good information that may useful to the investigator.  If more locations 
    // are identified, they can be added to this list.
	NSArray *propertyListPaths = [NSArray arrayWithObjects:@"/Library/Preferences", @"/Library/Preferences/SystemConfiguration", nil];
    
	for (NSString *plistPath in propertyListPaths)
	{
		LogDebugObjc(@"Attempting to copy property list files from path: %@\n", plistPath);
        
        // do a quick check to make sure we have enough space
        unsigned long long freeSpace = [[Utility getFileSystemFreeSpace:[self moduleCasePath]] unsignedLongLongValue];
        unsigned long long dirSize = [[Utility getDirectorySize:plistPath] unsignedLongLongValue];
        
        if (dirSize <= freeSpace)
        {
            NSFileManager *fm = [NSFileManager defaultManager];			
            NSArray *files = [fm contentsOfDirectoryAtPath:plistPath error:NULL];

            for(NSString *file in files) 
            {
                NSString *path = [plistPath stringByAppendingPathComponent:file];
			
                // for each plist file in the target directories, attempt to retrieve
                if ([[path pathExtension] isEqualToString:@"plist"])
                {
                    LogDebugObjc(@"Property List: %@\n", path);
				
                    // set the new path to the module output path
                    NSString *newPath = [[self moduleCasePath] stringByAppendingPathComponent:file];
				
                    // use LiveFile to copy the file
                    [LiveFile copyPlistFile:path toPath:newPath];
				
                    [LiveFile setFileReadOnly:newPath];
				
                    [self xmlInsertStartTag:@"propertyList" withLevel:2];
                    [self xmlInsertCompleteTag:@"filePath" withLevel:3 withString:path];
                    [self xmlInsertCompleteTag:@"casePath" withLevel:3 withString:newPath];
                    [self xmlInsertEndTag:@"propertyList" withLevel:2];
                }
            }
        }
        else
        {
            LogDebugObjc(@"Unable to copy property list files from %@ due to lack of free space\n", plistPath);
            
            double dirSizeGB = (dirSize * 1.0) / (1024.0) / (1024.0) / (1024.0);
            double freeSpaceGB = (freeSpace * 1.0) / (1024.0) / (1024.0) / (1024.0);
            
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setMessageText:[NSString stringWithFormat:@"Directory Size: %.02fG\nFree Space Available: %.02fG", dirSizeGB, freeSpaceGB]];
            [alert setInformativeText:@"Unable to copy property list files due to lack of free space available!"];
            [alert setAlertStyle:NSWarningAlertStyle];
            
            [alert runModal];
            [alert release];
        }
	}
	
	[self xmlInsertEndTag:@"propertyLists" withLevel:1];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end
