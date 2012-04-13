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

#import "AppController.h"
#import "CollectionModule.h"
#import "CaseLog.h"

#include <CommonCrypto/CommonDigest.h>

@implementation CollectionModule

@synthesize moduleName, moduleShortName, moduleEnabled, baseCasePath, cancelAcquisition;

- (id)init
{
	[super init];
	[self setModuleName: @"Generic Module"];
	[self setModuleShortName:@"GenericModule"];
	[self setModuleEnabled: FALSE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	[self setCancelAcquisition: FALSE];
	
	moduleXML = nil;
	lastProgressUpdate = 0.0;
	return self;
}

// Update from 0-100
// Negative value sets progress bar to indeterminate
- (void)updateProgress:(double) progressPercent
{
	if (progressPercent > 100.0) {
		return;
	}
	
	LogDebugObjc(@"progress %f\n", progressPercent);
	
    if (progressPercent < 0.0) {
        //set indeterminate
        [AppController updateModuleProgress:progressPercent];
        return;
    }
    
	// only update if .25% increase or more
	if (progressPercent >= (lastProgressUpdate + 0.25) || (progressPercent == 0.0)) {
		LogDebugObjc(@"updateModuleProgress-go\n");
		[AppController updateModuleProgress:progressPercent];
		lastProgressUpdate = progressPercent;
	}	
}

- (collectionmodule_status_t)moduleStatus
{
	return moduleStatus;
}

- (void)setModuleStatus:(collectionmodule_status_t)status
{
	moduleStatus = status;
	[AppController updateModuleStatus];
}

- (NSString *)moduleStatusString
{
	switch (moduleStatus)
	{
		case COLLECTIONMODULE_STATUS_OK:
			return @"OK";
		case COLLECTIONMODULE_STATUS_ACQUISITION_IN_PROGRESS:
			return @"Acquisition in progress...";
		case COLLECTIONMODULE_STATUS_ACQUISITION_COMPLETE:
			return @"Acquisition complete!";
		case COLLECTIONMODULE_STATUS_ACQUISITION_SKIPPED:
			return @"Module not selected - Skipped!";
		case COLLECTIONMODULE_STATUS_ACQUISITION_CANCELLED:
			return @"Acquisition cancelled by user!";
		case COLLECTIONMODULE_STATUS_WARNING_INSUFFICIENT_PERMISSIONS:
			return @"WARNING: PERMISSION LIMITED";
		case COLLECTIONMODULE_STATUS_DISABLED_INSUFFICIENT_PERMISSIONS:
			return @"DISABLED: INSUFFICIENT PERMISSIONS";
		case COLLECTIONMODULE_STATUS_DISABLED_BY_DEFAULT:
			return @"DISABLED: MODULE DISABLED BY DEFAULT";
		case COLLECTIONMODULE_STATUS_ERROR:
			return @"ERROR: UNKNOWN ERROR OCCURED";
		case COLLECTIONMODULE_STATUS_UNABLE_TO_OPEN_XML_FILE:
			return @"ERROR: UNABLE TO OPEN XML FILE!";
		case COLLECTIONMODULE_STATUS_UNABLE_TO_CREATE_MODULE_CASE_DIRECTORY:
			return @"ERROR: UNABLE TO CREATE MODULE CASE DIRECTORY";
		case COLLECTIONMODULE_STATUS_ERROR_LOW_DISK_SPACE:
			return @"ERROR: UNABLE TO COMPLETE - LOW DISK SPACE";
		case COLLECTIONMODULE_STATUS_ERROR_UNSUPPORTED_OS_VERSION:
			return @"ERROR: UNSUPPORTED OS VERSION!";
		default:
			return @"ERROR: UNSPECIFIED ERROR OCCURRED\n";
	}
	
	return @"ERROR: UNKNOWN ERROR OCCURED";
}

- (NSString *)moduleXmlFilePath /* $casePath/$moduleShortName.xml */
{
	return [NSString stringWithFormat:@"%@%@.xml", baseCasePath, moduleShortName];
}

- (NSString *)moduleCasePath /* $casePath/$moduleShortName/ */
{
	return [NSString stringWithFormat:@"%@%@/", baseCasePath, moduleShortName];
}

- (collectionmodule_status_t)casePathCreate
{
	if (![[NSFileManager defaultManager] createDirectoryAtPath:[self moduleCasePath] withIntermediateDirectories:YES attributes:nil error:nil])
	{
		LogDebugObjc(@"unable to create directory...\n");
		[self setModuleStatus:COLLECTIONMODULE_STATUS_UNABLE_TO_CREATE_MODULE_CASE_DIRECTORY];
		return COLLECTIONMODULE_STATUS_UNABLE_TO_CREATE_MODULE_CASE_DIRECTORY;
	}
	
	return COLLECTIONMODULE_STATUS_OK;
}

- (collectionmodule_status_t)xmlOpen
{
	moduleXML = [LiveXML allocLiveXMLWith:[self moduleXmlFilePath]];
	
	if (moduleXML == nil) {
		[self setModuleStatus:COLLECTIONMODULE_STATUS_UNABLE_TO_OPEN_XML_FILE];
		[AppController updateModuleProgress:100.0];
		return COLLECTIONMODULE_STATUS_UNABLE_TO_OPEN_XML_FILE;
	}
	
	NSString *moduleTag = [NSString stringWithFormat: @"<%@Module>\n", [self moduleShortName]];
	[moduleXML writeString:moduleTag];
	
	return COLLECTIONMODULE_STATUS_OK;
}

- (void)xmlWriteString:(NSString *)str
{
	[moduleXML writeString:str];
}

- (void)xmlInsertTabs:(UInt32)level
{
	[moduleXML insertTabs:level];
}

- (void)xmlInsertStartTag:(NSString *)tagName withLevel:(UInt32)level
{
	[moduleXML insertStartTag:tagName withLevel:level];
}

- (void)xmlInsertEndTag:(NSString *)tagName withLevel:(UInt32)level
{
	[moduleXML insertEndTag:tagName withLevel:level];
}

- (void)xmlInsertCompleteTag:(NSString *)tagName withLevel:(UInt32)level withString:(NSString *)dataString 
{
	[moduleXML insertCompleteTag:tagName withLevel:level withString:dataString];
}

- (collectionmodule_status_t) xmlClose
{
	[self xmlInsertEndTag:[NSString stringWithFormat:@"%@Module", [self moduleShortName]] withLevel:0];
	
	[moduleXML hash];
	
	[moduleXML close];	
	
	[LiveFile setFileReadOnly:[self moduleXmlFilePath]];
	
	[moduleXML release];
	moduleXML = nil;
	
	return COLLECTIONMODULE_STATUS_OK;
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{	
	NSString *caseLog_start = [NSString stringWithFormat:@"Starting module: %@", [self moduleName]];
	CaseLog_WriteMessage(caseLog_start);
	
	[self updateProgress:0.0];
	[self setBaseCasePath: outputPath];
	
	useCompression = compressionEnabled;
	
	LogDebugObjc(@"%@ - acquireDataToPath: %@\n", [self moduleShortName], [self baseCasePath]);
	
	[self setModuleStatus: COLLECTIONMODULE_STATUS_ACQUISITION_IN_PROGRESS];

	return [self xmlOpen];
}

- (void)acquisitionComplete
{
	[self updateProgress:100.0];
	[self xmlClose];
	
	NSString *caseLog_end = [NSString stringWithFormat:@"Module complete: %@", [self moduleName]];
	CaseLog_WriteMessage(caseLog_end);
	
	[self setModuleStatus: COLLECTIONMODULE_STATUS_ACQUISITION_COMPLETE];
}

@end
