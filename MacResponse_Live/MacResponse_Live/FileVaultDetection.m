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

#import "FileVaultDetection.h"
#import "CaseLog.h"
#import <pwd.h>

@implementation FileVaultDetection

- (id)init
{
	[super init];
	[self setModuleName: @"FileVault Detection"];
	[self setModuleShortName:@"FileVault"];	
	[self setModuleEnabled: TRUE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
    
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
	
	int uid = getuid();
	struct passwd *pw = getpwuid(uid);
	NSString *currentUser = [NSString stringWithFormat:@"%s", pw->pw_name];
		
	// Create a dictionary and populate it with data from the loginwindow 
	//  property list file
	NSString *plistPath = @"/Library/Preferences/com.apple.loginwindow.plist";
	NSDictionary *plistDict = [[NSDictionary alloc] initWithContentsOfFile:plistPath];	
	
	// If there any any FileVault users currently logged in, there will be a 
	// dictionary with Key:FileVaultLoggedInUsers
	NSDictionary *fvUsers = [plistDict objectForKey:@"FileVaultLoggedInUsers"];
	
	[self xmlInsertStartTag:@"fileVaultLoggedInUsers" withLevel:1];

	if (fvUsers)
	{
		LogDebugObjc(@"Found logged in users with FileVault encryption\n");
		
		// Enumerate through the FileVault users that are currently 
		// logged in
		NSEnumerator *keyEnum = [fvUsers keyEnumerator];
		id key;
		
		// Information for FileVault users will be an array of data with 
		// a key matching the users login name
		while ((key = [keyEnum nextObject]))
		{
			LogDebugObjc(@"User: %@\n", key);
			
			[self xmlInsertStartTag:@"fileVaultLoggedInUser" withLevel:2];
			[self xmlInsertCompleteTag:@"userName" withLevel:3 withString:[NSString stringWithFormat:@"%@", key]];
			
			// get array of values associated with this user
			// these values pertain to the location of the sparsebundle, and where it is mounted when decrypted
			NSArray *values = [fvUsers objectForKey:key];

			// for now, assume that there are two values...
			//  have not come accross any examples that indicate otherwise
			//
			//   value[0] = mount point
			//   value[1] = sparsebundle location
			if ([values count] < 2)
			{
				LogDebugObjc(@"Inconsistent data retrieved about this FV user (%@)\n", key);
			}
			else 
			{
				[self xmlInsertCompleteTag:@"mountPoint" withLevel:3 withString:[values objectAtIndex:0]];
				[self xmlInsertCompleteTag:@"sparsebundle" withLevel:3 withString:[values objectAtIndex:1]];
			}
			
			BOOL homeDirCopied = FALSE;
			
			// check if this FileVault user is the current user
			if ([key isEqualToString:currentUser])
			{
				LogDebugObjc(@"Current user has FileVault enabled\n");
				
				// Check for size of home directory
				unsigned long long homeSize = [[Utility getDirectorySize:NSHomeDirectory()] unsignedLongLongValue];
				double homeSizeGB = (homeSize * 1.0) / (1024.0) / (1024.0) / (1024.0);
				
				// Check for available space at location where data may be copied to
				unsigned long long freeSpace = [[Utility getFileSystemFreeSpace:[self baseCasePath]] unsignedLongLongValue];
				double freeSpaceGB = (freeSpace * 1.0) / (1024.0) / (1024.0) / (1024.0);
				
				LogDebugObjc(@"Home Directory Size: %.02fG\n", homeSizeGB);
				LogDebugObjc(@"Free Space Available: %.02fG\n", freeSpaceGB);
				
				if (homeSize > freeSpace)
				{
					LogDebugObjc(@"Unable to copy home directory due to lack of free space\n");

					NSAlert *alert = [[NSAlert alloc] init];
					[alert setMessageText:[NSString stringWithFormat:@"Home Directory Size: %.02fG\nFree Space Available: %.02fG", homeSizeGB, freeSpaceGB]];
					[alert setInformativeText:@"Unable to copy home directory due to lack of free space available!"];
					[alert setAlertStyle:NSWarningAlertStyle];
				
					[alert runModal];
					[alert release];
				}				
				else 
				{
					homeDirCopied = TRUE;

                    // Copy directory recursively, using LiveFile
                    // May want to create top level 'home' directory in the moduleCasePath
                    [LiveFile copyDirectory:NSHomeDirectory() toPath:[self moduleCasePath] withCasePath:[self baseCasePath] withCompression:useCompression];
                }
			}
			
			if (homeDirCopied)
			{
				[self xmlInsertCompleteTag:@"homeDirectoryCopied" withLevel:3 withString:@"TRUE"];
			}
			else 
			{
				[self xmlInsertCompleteTag:@"homeDirectoryCopied" withLevel:3 withString:@"FALSE"];
			}
            
            [self xmlInsertEndTag:@"fileVaultLoggedInUser" withLevel:2];
		}
	}
	
	[self xmlInsertEndTag:@"fileVaultLoggedInUsers" withLevel:1];
	
	[plistDict release];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end
