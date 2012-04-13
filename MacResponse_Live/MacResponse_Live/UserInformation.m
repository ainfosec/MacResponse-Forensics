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

#import <pwd.h>
#import "UserInformation.h"
#import "CaseLog.h"

@implementation UserInformation

- (id)init
{
	[super init];
	[self setModuleName: @"User Information"];
	[self setModuleShortName:@"UserInformation"];		
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
    
    // This module merely looks in the /Users directory and takes inventory on the
    // home directories taht exists on the system
	
	NSError  *error = nil;
	NSFileManager *manager = [NSFileManager defaultManager];
    
    // Get the files/directories at /Users
	NSArray *files = [manager contentsOfDirectoryAtPath:@"/Users" error:&error];
	
	if (error) 
	{
		LogDebugObjc(@"error getting user information %@\n");
		LogDebugObjc(@"localizedDescription = %@\n", [error localizedDescription]);
		LogDebugObjc(@"localizedFailureReason = %@\n", [error localizedFailureReason]);
		
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"users" withLevel:1];
	for (NSString *file in files)
	{
        // Take note of all items that are note 'Shared' and that do not
        // begin with a '.'
		if ((![file hasPrefix:@"."]) && (![file isEqualToString:@"Shared"]))
		{
			[self xmlInsertStartTag:@"user" withLevel:2];
			LogDebugObjc(@"User: %@\n", file);
			
			[self xmlInsertCompleteTag:@"userName" withLevel:3 withString:file];
			
            // we are currently only getting the uid and gid for this user,
            // future releases may get more information
			struct passwd *pw = getpwnam([file UTF8String]);
			[self xmlInsertCompleteTag:@"uid" withLevel:3 withString:[NSString stringWithFormat:@"%d", pw->pw_uid]];
			[self xmlInsertCompleteTag:@"gid" withLevel:3 withString:[NSString stringWithFormat:@"%d", pw->pw_gid]];

			[self xmlInsertEndTag:@"user" withLevel:2];
		}
	}
	[self xmlInsertEndTag:@"users" withLevel:1];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}
@end

