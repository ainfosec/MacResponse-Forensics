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

#import <Cocoa/Cocoa.h>
#import "ListApps.h"
#import	"CaseLog.h"


// We have a decent idea apx. how long it will take... we can guess
// progress instead of using an indeterminate progress
#define GUESS_PROGRESS 1

@implementation ListApps

- (id)init
{
	[super init];
	[self setModuleName: @"Spotlight Application List"];
	[self setModuleShortName:@"SpotlightApplicationList"];
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
    
#ifndef GUESS_PROGRESS
    [self updateProgress:-1.0];
#endif
    
	// This module takes advantage of the Spotlight utility
	NSString *predicateFormat = @"(kMDItemKind like %@) or (kMDItemKind like %@)";
	NSString *searchString1 = @"Application";
	NSString *searchString2 = @"Unix Executable File";
	
	// NSMetadataQuery is similar to a database query, using an NSPredicate to build 
	//  the query structure
	//
	// In this case, we are looking for all files on the system that have a
	//  kMDItemKind of either "Application" (.app) or "Unix Executable File" (binary)
	NSPredicate *predicate = [NSPredicate predicateWithFormat: predicateFormat, searchString1, searchString2, nil];
	
	query = [[NSMetadataQuery alloc] init];
	[query setPredicate: predicate];
	
	// In order to get the results back from the query, we need to attach
	//  a notification observer to the query, which will send all 
	//  notifications associated with the query to a query handler
	NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
	[nc addObserver:self
		   selector:@selector(queryHandler:)
			   name:nil
			 object:query];
	
	[query startQuery];
	
	// CFRunLoopRun will put the query in a loop so we can properly
	//  listen for notifications and wait patiently for the 
	//  query to finish
	CFRunLoopRun();
	
	[query release];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

-(void)queryHandler:(NSNotification *)notification
{
	LogDebugObjc(@"Received notification from metadata query\n");
	
	if ([[notification name] isEqualToString:NSMetadataQueryDidStartGatheringNotification])
	{
		LogDebugObjc(@"Notification: Query Started\n");
	}
	else if ([[notification name] isEqualToString:NSMetadataQueryGatheringProgressNotification])
	{
		LogDebugObjc(@"Notification: Still Gathering\n");
	}
	else if ([[notification name] isEqualToString:NSMetadataQueryDidUpdateNotification])
	{
		LogDebugObjc(@"Notification: Update happened\n");
	}
	else if ([[notification name] isEqualToString:NSMetadataQueryDidFinishGatheringNotification])
	{
		// The query is finished, go parse the results
		LogDebugObjc(@"Notfication: Query Finished\n");
		CFRunLoopStop(CFRunLoopGetCurrent());
		[self parseResults];
	}
	else
	{
		// Received an unknown notification, kill the loop and return
		LogDebugObjc(@"Notifcation: %@\n", notification);
		CFRunLoopStop(CFRunLoopGetCurrent());
	}

}

-(NSString *)getMetaData:(NSMetadataItem *)item withAttr:(NSString *)attr
{
    return [item valueForAttribute:attr];
}

-(void)parseResults
{
	LogDebugObjc(@"Parsing metadata query results\n");

#ifdef GUESS_PROGRESS
	double percentComplete = 10.0;
	[self updateProgress:percentComplete];
#endif
	
	[self xmlInsertStartTag:@"applications" withLevel:1];
	
	NSUInteger countResults = [[query results] count];
	
	// get number for every 5% up to 95% (remember we are starting at 10% at this point)
	unsigned long countToAdjust = countResults / 17;
	
	int resultCounter = 0;
	
	for (NSMetadataItem *app in [query results])
	{
		NSAutoreleasePool *innerPool = [[NSAutoreleasePool alloc] init];

		// assume query worked as should and that there are only two types returned:
		//   ** Application
		//   ** Unix Executable File
		NSString *type;
		if ([[app valueForAttribute:(NSString *)kMDItemKind] isEqualToString:@"Application"])
		{
			type = @"application";
		}
		else 
		{
			type = @"binary";
		}

		[self xmlInsertStartTag:@"application" withLevel:2];

		[self xmlInsertCompleteTag:@"applicationName" withLevel:3 withString:[app valueForAttribute:(NSString *)kMDItemDisplayName]];

        [self xmlInsertCompleteTag:@"applicationType" withLevel:3 withString:type];
		
        NSString *path = [app valueForAttribute:(NSString *)kMDItemPath];
        
        if (path)
        {
            [self xmlInsertCompleteTag:@"filePath" withLevel:3 withString:path];
        }
		
        NSDate *d = [app valueForAttribute:(NSString *)kMDItemContentModificationDate];
        
        if (d)
        {
            [self xmlInsertCompleteTag:@"lastModifiedDate" withLevel:3 withString:[d description]];
        }
		 
		NSString *version = [app valueForAttribute:(NSString *)kMDItemVersion];
		if (version)
		{
			[self xmlInsertCompleteTag:@"applicationVersion" withLevel:3 withString:version];
		}
		
		[self xmlInsertEndTag:@"application" withLevel:2];
		
		resultCounter++;
		if (resultCounter == countToAdjust)
		{
			resultCounter = 0;
#ifdef GUESS_PROGRESS
			percentComplete += 5.0;
			[self updateProgress:percentComplete];
#endif
		}
		
		[innerPool drain];
	}
	
	[self xmlInsertEndTag:@"applications" withLevel:1];
}

@end