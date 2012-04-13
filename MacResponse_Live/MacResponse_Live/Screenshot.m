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

#import "Screenshot.h"
#import "CaseLog.h"

@implementation Screenshot

- (id)init
{
	[super init];
	[self setModuleName: @"Screenshot"];
	[self setModuleShortName:@"Screenshot"];		
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
	
    // capture the screenshot and convert to a bitmap
	CGImageRef screenShot = CGWindowListCreateImage(CGRectInfinite, kCGWindowListOptionOnScreenOnly, kCGNullWindowID, kCGWindowImageDefault);
	NSBitmapImageRep *bitmapRep = [[NSBitmapImageRep alloc] initWithCGImage:screenShot];
	CGImageRelease(screenShot);
	
    // store bitmap in an NSData object
	NSString *screenshotPath = [[self moduleCasePath] stringByAppendingPathComponent:@"screenshot.jpeg"];	
	NSData *data = [bitmapRep representationUsingType:NSJPEGFileType properties:nil];
	
	[bitmapRep release];
	
    // write bitmap to file
	LiveFile *lf = nil;
	lf = [LiveFile allocLiveFileCreate:screenshotPath withCompression:useCompression];
	[lf write:data];
	[lf close];
	
	[LiveFile setFileReadOnly:screenshotPath];
	
    // if useCompress is true, we still need to append a '.gz' to the end of
    // the file to indicate as such (compression was handled by LiveFile
    // in the calls above)
	if (useCompression)
	{
		screenshotPath = [screenshotPath stringByAppendingString:@".gz"];
	}
	
	[self xmlInsertCompleteTag:@"casePath" withLevel:1 withString:screenshotPath];
		
	[lf release];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}
@end