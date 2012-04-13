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

#import <Foundation/Foundation.h>
#import "LiveLog.h"
#import "Utility.h"
#import "LiveFile.h"
#import "LiveXML.h"
#import "CaseLog.h"

typedef enum
{
	COLLECTIONMODULE_STATUS_OK = 0, // all is well
	
	// non-error status (>=0)
	COLLECTIONMODULE_STATUS_ACQUISITION_IN_PROGRESS = 1,
	COLLECTIONMODULE_STATUS_ACQUISITION_COMPLETE = 2,
	COLLECTIONMODULE_STATUS_ACQUISITION_SKIPPED = 3,
	COLLECTIONMODULE_STATUS_ACQUISITION_CANCELLED = 4,
	
	// error status (< 0)
	COLLECTIONMODULE_STATUS_WARNING_INSUFFICIENT_PERMISSIONS = -1, // warn user they may not get all the data
	COLLECTIONMODULE_STATUS_DISABLED_INSUFFICIENT_PERMISSIONS = -2, // do not attempt to execute module with current permissions
	COLLECTIONMODULE_STATUS_DISABLED_BY_DEFAULT = -3, // if there is any reason to have a module disabled by default...
	COLLECTIONMODULE_STATUS_ERROR = -4, // some error during execution - see [errorInfoString]
	COLLECTIONMODULE_STATUS_UNABLE_TO_OPEN_XML_FILE = -5,
	COLLECTIONMODULE_STATUS_UNABLE_TO_CREATE_MODULE_CASE_DIRECTORY = -6,
	COLLECTIONMODULE_STATUS_ERROR_LOW_DISK_SPACE = -7,
	COLLECTIONMODULE_STATUS_ERROR_UNSUPPORTED_OS_VERSION = -8,

	//...
	COLLECTIONMODULE_STATUS_CUSTOM_MODULE_ERROR = -1000, // custom errors start at -1000
		
} collectionmodule_status_t;

@interface CollectionModule : NSObject {
	NSString *baseCasePath; // case output path as specified to acquireDataToPath
	NSString *moduleName;  // name for gui purposes [eg. Phyiscal Memory (RAM)]
	NSString *moduleShortName; // name for output purposes [eg. PhysicalMemory]
	
	Boolean moduleEnabled; // enabled in the gui
	
	LiveXML *moduleXML;
	
	collectionmodule_status_t moduleStatus; // current module status
	
	Boolean cancelAcquisition; // allows appcontroller to tell module to cancel its acquisition
	
	Boolean useCompression; // whether or not we use compression
	
	double lastProgressUpdate;
}

@property (readwrite, copy) NSString *baseCasePath;
@property (readwrite, copy) NSString *moduleName;
@property (readwrite, copy) NSString *moduleShortName;

@property (readwrite, assign) Boolean moduleEnabled;
//@property (readwrite, assign) collectionmodule_status_t moduleStatus;
@property (readwrite, assign) Boolean cancelAcquisition;

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled;

- (void)acquisitionComplete;

- (collectionmodule_status_t)casePathCreate;

- (collectionmodule_status_t)xmlOpen;

- (collectionmodule_status_t)xmlClose;

- (NSString *)moduleXmlFilePath; /* $casePath/$moduleShortName.xml */

- (NSString *)moduleCasePath; /* $casePath/$moduleShortName/ */

- (NSString *)moduleStatusString;

- (void)xmlWriteString:(NSString *)str;

- (void)xmlInsertTabs:(UInt32)level;

- (void)xmlInsertStartTag:(NSString *)tagName withLevel:(UInt32)level;

- (void)xmlInsertEndTag:(NSString *)tagName withLevel:(UInt32)level;

- (void)xmlInsertCompleteTag:(NSString *)tagName withLevel:(UInt32)level withString:(NSString *)dataString;

- (void)updateProgress:(double) progressPercent;

- (collectionmodule_status_t)moduleStatus;

- (void)setModuleStatus:(collectionmodule_status_t)status;

@end
