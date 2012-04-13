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
#import "CollectionModule.h"

@interface AppController : NSObject {
	IBOutlet NSButton *debugButton;
	
	IBOutlet NSTextField *outputPathLabel;
	
	IBOutlet NSTextField *userId;
	IBOutlet NSTextField *effectiveUserId;
	IBOutlet NSTextField *availableDiskSpace;
	
	IBOutlet NSTextField *examinerName;
	IBOutlet NSTextField *caseCurrentDateTime;
	IBOutlet NSTextField *caseSystemDateTime;
	IBOutlet NSTextField *caseIdentifier;
	IBOutlet NSTextView *caseNotes;
	IBOutlet NSPathControl *outputPathControl;
	IBOutlet NSProgressIndicator *progressIndicator;
	IBOutlet NSButton *startButton;
	IBOutlet NSButton *stopButton;
	IBOutlet NSArrayController *arrayController;
	IBOutlet NSTableView *tableView;
	IBOutlet NSTextField *progressIndicatorText;
	
	IBOutlet NSWindow *window;
	IBOutlet NSButton *enableDisableAllButton;

	IBOutlet NSButton *optionEnableCompression;
	IBOutlet NSButton *optionEnableDebugLogging;
	
	NSFileManager *fileManager;
	NSMutableArray *collectionModules;
	Boolean acquisitionInProgress;
	NSString *baseOutputString;	// Without case identifier appended
	
	CollectionModule *currentlyRunningModule;

	Boolean appControllerReady; // awakeFromNib completed
}

- (IBAction)enableDisableAll:(id)sender;
- (IBAction)startAcquisition:(id)sender;
- (IBAction)stopAcquisition:(id)sender;
- (IBAction)debugButton:(id)sender;

+ (void)updateModuleProgress:(double) progressPercent;
+ (void)updateModuleStatus; // redraw table

@property (readwrite, copy) NSString *baseOutputString;

@end
