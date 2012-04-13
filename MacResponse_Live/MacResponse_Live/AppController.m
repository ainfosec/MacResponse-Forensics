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
#import "LiveLog.h"

#import "Screenshot.h"
#import "SystemDateTime.h"
#import "NetworkConfiguration.h"
#import "FileVaultDetection.h"
#import "PhysicalMemory.h"
#import "ListApps.h"
#import "PropertyLists.h"
#import "SystemControl.h"
#import "LoadedDrivers.h"
#import "ProcessInfo.h"
#import "NetworkConnections.h"
#import "Utility.h"
#import "LoginSessions.h"
#import "UserInformation.h"
#import "DiskInformation.h"
#import "CaseLog.h"
#import "FilesystemInfo.h"

#include <unistd.h>

static AppController * singletonInstance = nil;

@implementation AppController

@synthesize baseOutputString;

- (void)alertUser: (NSString *)messageText
{
	LogDebugObjc(@"alertUser %@\n", messageText);

	NSAlert *alert = [[NSAlert alloc] init];
	[alert addButtonWithTitle:@"OK"];
	[alert setMessageText:@"[ERROR]"];
	[alert setInformativeText:messageText];
	[alert setAlertStyle:NSWarningAlertStyle];
	
	[alert runModal];
	[alert release];
}

- (id)init
{
	[super init];
	
    appControllerReady = NO;
    currentlyRunningModule = nil;
	acquisitionInProgress = NO;
    singletonInstance = self;
    [self setBaseOutputString:nil];
    
    CollectionModule *collectionModule;
    
    fileManager = [[NSFileManager alloc] init];
	collectionModules = [[NSMutableArray alloc] init];
	
	// NETWORK CONNECTIONS
	collectionModule = [[NetworkConnections alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// LOGIN SESSIONS
	collectionModule = [[LoginSessions alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// SCREENSHOT
	collectionModule = [[Screenshot	alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// PHYSICAL MEMORY
	collectionModule = [[PhysicalMemory alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// PROCESS INFORMATION
	collectionModule = [[ProcessInfo alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// DRIVER INFORMATION
	collectionModule = [[LoadedDrivers alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// DISK INFORMATION
	collectionModule = [[DiskInformation alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// APPLICATION LIST
	collectionModule = [[ListApps alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// NETWORK CONFIGURAITON
	collectionModule = [[NetworkConfiguration alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// SYSTEM INFORMAITON
	collectionModule = [[SystemControl alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// USER INFORMATION
	collectionModule = [[UserInformation alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
	
	// FILEVAULT DETECTION
	collectionModule = [[FileVaultDetection alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];

	// PROPERTY LISTS	
	collectionModule = [[PropertyLists alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
    
    // FILESYSTEM INFO
	collectionModule = [[FilesystemInfo alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
    
	// SYSTEM DATE AND TIME
	collectionModule = [[SystemDateTime alloc] init];
	[collectionModules addObject:collectionModule];
	[collectionModule release];
		
	return self; 
}

- (NSString *)myAppendPath:(NSString *)basePath withComponent:(NSString *)component
{
	LogDebugObjc(@"myAppendPath: %@\n", basePath);
	
	// strip any suffix '/'
	while ([basePath hasSuffix:@"/"])
	{
		basePath = [basePath substringToIndex:([basePath length] - 1)];
		LogDebugObjc(@"stripping /\n");
	}

	LogDebugObjc(@"myAppendPath: %@\n", basePath);
	
	// re-add a single '/' and component name, if available
	if ([component isEqualToString:@""])
	{
		basePath = [basePath stringByAppendingFormat:@"/"];
	}
	else 
	{
		basePath = [basePath stringByAppendingFormat:@"/%@/", component];
	}

	return basePath;	
}

- (NSString *)casePathString
{
	return [self myAppendPath:baseOutputString withComponent:[caseIdentifier stringValue]];
}

- (NSURL *)casePathURL
{
	// now generate url
	NSString *path = [self casePathString];
	
	LogDebugObjc(@"casePathString = %@\n", path);
	
	NSURL *url = [NSURL URLWithString:path];
	
	LogDebugObjc(@"url = %@\n", url);
	
	return url;
}

- (BOOL)checkCasePathExists:(BOOL *)isDirectory
{
	BOOL ret, isDir;
	NSString *casePath = [self casePathString];
	
	LogDebugObjc(@"Checking %@\n", casePath);
		
	ret = [fileManager fileExistsAtPath:casePath isDirectory:&isDir];	
	
	if (isDirectory)
	{
		*isDirectory = isDir;
	}
	
	return ret;
}

- (void)updateDiskSpace:(NSString *)errorString
{
	if (errorString) {
		[availableDiskSpace setTextColor:[NSColor redColor]];
		[availableDiskSpace setStringValue:errorString];
	} else {
		[availableDiskSpace setTextColor:[NSColor blackColor]];
		
		unsigned long long freeSpaceBytes = [[Utility getFileSystemFreeSpace:baseOutputString] unsignedLongLongValue];
		double freeSpaceGB = (freeSpaceBytes * 1.0) / (1024.0) / (1024.0) / (1024.0);
		
		LogDebugObjc(@"available disk space %f (0x%llx)\n", freeSpaceGB, freeSpaceBytes);
		[availableDiskSpace setStringValue:[NSString stringWithFormat:@"Available Disk Space: %.02f GB\n", freeSpaceGB]];
	}
}

- (void)updateOutputPath:(NSString *)basePath
{
	LogDebugObjc(@"updateOutputPaths... %@ %@\n", basePath, [caseIdentifier stringValue]);
	
	// ensure that base output string is formatted correctly
    [self setBaseOutputString:[basePath stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
	
	LogDebugObjc(@" baseOutputSTring = %@\n", baseOutputString);
	LogDebugObjc(@" casePathString = %@\n", [self casePathString]);
	LogDebugObjc(@" casePathURL = %@\n", [self casePathURL]);
	
	[outputPathControl setURL:[self casePathURL]];	
	
	LogDebugObjc(@"new url = %@\n", [outputPathControl URL]);
	
	NSArray *pathComponentCells = [outputPathControl pathComponentCells];
	NSPathComponentCell *cell = [pathComponentCells lastObject];
	
	/* override last component to be a directory if it is the case identifier */
	if (![[caseIdentifier stringValue] isEqualToString:@""])
	{
		NSImage *image = [[NSWorkspace sharedWorkspace] iconForFileType:NSFileTypeForHFSTypeCode(kGenericFolderIcon)];
		[image setSize:NSMakeSize(16, 16)];
		[cell setImage:image];
	}	
	
	[self updateDiskSpace:FALSE];

	// pre-emptively check for path errors
	if (![[caseIdentifier stringValue] isEqualToString:@""])
	{
		BOOL isDir = 0;
		BOOL exists = 0;
		
		// check to see if base path is legit
        NSString *pathCheck = [self baseOutputString];
		exists = [fileManager fileExistsAtPath:pathCheck isDirectory:&isDir];
		
		if (!exists || !isDir)
		{
			// base path doesn't exist...
			LogDebugObjc(@"base path error! %@ %d %d\n", pathCheck, exists, isDir);
			[self updateDiskSpace:@"*Invalid Output Path!*"];
			[startButton setEnabled:NO];
		}
		else if ([self checkCasePathExists:NULL])
		{
			[self updateDiskSpace:@"*Case Directory Already Exists!*"];
			[caseIdentifier setTextColor:[NSColor redColor]];
			[startButton setEnabled:NO];
		}
		else 
		{
			[self updateDiskSpace:nil];
			[caseIdentifier setTextColor:[NSColor blackColor]];
			[startButton setEnabled:YES];
		}
	}
}

- (void)awakeFromNib
{
	NSString *dateTime = [[NSDate date] description];
	
    [caseNotes setRichText:NO];
	[startButton setEnabled:YES];
	[stopButton setEnabled:NO];
	[caseCurrentDateTime setStringValue: dateTime];
	[caseSystemDateTime setStringValue: dateTime];
	
	[outputPathControl setDoubleAction:@selector(openPathDialog:)];
	[outputPathControl setTarget:self];
	
	NSString *path = [[NSBundle mainBundle] bundlePath];

	LogDebugObjc(@"bundle path: %@\n", path);

	path = [path stringByDeletingLastPathComponent];

	[self updateOutputPath:path];
	
	LogDebugObjc(@"check uid\n");
	
	[userId setStringValue:[NSString stringWithFormat:@"User ID: %d\n", getuid()]];
	[effectiveUserId setStringValue:[NSString stringWithFormat:@"Effective User ID: %d\n", geteuid()]];
	
	LogDebugObjc(@"bring window to forefront\n");
	
	[tableView setUsesAlternatingRowBackgroundColors:YES];
	[tableView setAllowsEmptySelection:YES];
    
    [progressIndicator setIndeterminate:NO];
	[progressIndicator setDoubleValue:0.0];
	[progressIndicator setMinValue:0.0];
	[progressIndicator setMaxValue:100.0];
        
    // Bring the window to the forefront
	[NSApp activateIgnoringOtherApps:YES];
    
	appControllerReady = YES;
    
	LogDebugObjc(@"awakeFromNib complete!\n");
}

/**
 * controlTextDidChange - delegate for text fields (notably just case identifier for updating path...
 */
- (void)controlTextDidChange:(NSNotification *)nd
{
	LogDebugObjc(@"controlTextDidChange...\n");
	
	NSTextField *ed = [nd object];
	
	if (ed == caseIdentifier) {
		// we need to check for and scrub illegal characters
		NSString *caseIdString = [caseIdentifier stringValue];
		NSString *newCaseIdString = @"";
		int i;
		
		for (i = 0; i < [caseIdString length]; i++) {
			char c = [caseIdString characterAtIndex: i];
			
			if ((c >= 'a' && c <= 'z') || 
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				(c == '-') ||
				(c == '_'))
			{
				newCaseIdString = [newCaseIdString stringByAppendingFormat:@"%c", c];
			}
		}
		
		// use lastPathComponent for additional safety... shouldn't be required with above filtering
		[caseIdentifier setStringValue:[newCaseIdString lastPathComponent]];
		
		[self updateOutputPath:baseOutputString];
	}
};

- (void)openPathDialog:(id)sender
{
	LogDebugObjc(@"openPathDialog!\n");
	
	// Create the File Open Dialog class.
	NSOpenPanel* panel = [NSOpenPanel openPanel];
	
	[panel setAllowsMultipleSelection:NO];
    [panel setCanChooseDirectories:YES];
    [panel setCanChooseFiles:NO];
    [panel setResolvesAliases:YES];
    [panel setTitle:@"Select the Destination Output Directory"];
    [panel setPrompt:@"Select"];	
	
	// Display the dialog.  If the OK button was pressed,
	// process the files.
	if ( [panel runModal] == NSOKButton )
	{
		// Get an array containing the full filenames of all
		// files and directories selected.
		NSArray* paths = [panel URLs];
	
		NSURL *url = [paths objectAtIndex:0];
		LogDebugObjc(@"url = %@\n", url);

		NSString *string = [url absoluteString];
		LogDebugObjc(@"string = %@\n", string);	
		
		// TODO: chop off the 'file://localhost' - there has to be a better way.
		// if not, at least verify the existence of file:// chop it off, and remove component
		string = [string substringFromIndex:16];
		[self updateOutputPath:string];
	}
}

- (void)enableDisableAll:(id)sender
{
	LogDebugObjc(@"enableDisableAll...\n");
	
	unsigned long i, moduleCount = [collectionModules count];
	Boolean enableModules = [enableDisableAllButton state];
		
	if (enableModules)
	{
		enableModules = YES;
		LogDebugObjc(@"enabling all modules...\n");
	}
	else
	{
		enableModules = NO;
		LogDebugObjc(@"disabling all modules...\n");		
	}


	for (i = 0; i < moduleCount; i++)
	{
		CollectionModule *obj = [collectionModules objectAtIndex:i];
		[obj setModuleEnabled:enableModules];
	}
}

- (void)updateProgressBar:(NSNumber *)percent
{
    if ([percent doubleValue] < 0.0)
    {
        // set to indeterminate
        LogDebugObjc(@"setting progress bar to indeterminate...\n");
        [progressIndicator setIndeterminate:YES];
        [progressIndicator startAnimation:self];
        return;
    }
    
    [progressIndicator setIndeterminate:NO];
	[progressIndicator setDoubleValue:[percent doubleValue]];
    [progressIndicator startAnimation:self];
}

+ (void)updateModuleProgress:(double)progressPercent
{
	NSNumber *pp = [NSNumber numberWithDouble:progressPercent];
	
	[singletonInstance performSelectorOnMainThread:@selector(updateProgressBar:) withObject:pp waitUntilDone:YES];	
}

- (void)refreshTableView
{
	if (appControllerReady)
	{
		LogDebugObjc(@"refreshTableView refreshing table view\n");
		[tableView reloadData];
	}
}

+ (void)updateModuleStatus
{
	LogDebugObjc(@"updateModuleStatus refreshing table view\n");
	[singletonInstance performSelectorOnMainThread:@selector(refreshTableView) withObject:nil waitUntilDone:YES];
}

- (void)updateProgressText:(id)textString
{
	LogDebugObjc(@"updateProgressText: %@\n", textString);
	[progressIndicatorText setStringValue:textString];
}

- (void)finishedAcquisition
{
	[tableView reloadData];
	
#ifdef ALLOW_MULTIPLE_ACQUISIITONS
	[tableView setSelectionHighlightStyle:NSTableViewSelectionHighlightStyleRegular];
	[tableView setEnabled:YES];
	[examinerName setEnabled:YES];
	[caseIdentifier setEnabled:YES];
	[caseCurrentDateTime setEnabled:YES];
	[caseNotes setEnabled:YES];	
	[startButton setEnabled:YES];
	[optionEnableCompression setEnabled:YES];
	[optionEnableDebugLogging setEnabled:YES];
	[outputPathControl setEnabled:YES];
	[enableDisableAllButton setEnabled:YES];
#endif
	
	[stopButton setEnabled:NO];
}

- (void)acquisitionThread
{
    NSString *caseLogMessage;
    
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

	Boolean cancelledAcquisition = NO;
	unsigned int i = 0;
			
	@try 
	{
		[CaseLog initCaseLog:[NSString stringWithFormat:@"%@CaseLog.xml", [self casePathString]]];
		CaseLog_WriteMessage(@"Acquisition Start");
	}
	@catch (NSException *e)
	{
		[self alertUser:@"Unable to create case log file (low disk space)"];
		return;
	}
	
	NSString *caseLog_examiner = [NSString stringWithFormat:@"Examiner: %@", [examinerName stringValue]];
	CaseLog_WriteMessage(caseLog_examiner);
	
	NSString *caseLog_id = [NSString stringWithFormat:@"Case Identifier: %@", [caseIdentifier stringValue]];
	CaseLog_WriteMessage(caseLog_id);
	
	NSString *caseLog_outputDir = [NSString	 stringWithFormat:@"Output Directory: %@", [outputPathControl stringValue]];
	CaseLog_WriteMessage(caseLog_outputDir);
	
	NSString *caseLog_notes = [NSString stringWithFormat:@"Case Notes: %@", [[caseNotes textStorage] string]];
	CaseLog_WriteMessage(caseLog_notes);
	
	NSString *caseLog_compression = [NSString stringWithFormat:@"Compression enabled: "];
	
	if ([optionEnableCompression state])
	{
		caseLog_compression = [caseLog_compression stringByAppendingFormat:@"TRUE"];
	}
	else 
	{
		caseLog_compression = [caseLog_compression stringByAppendingFormat:@"FALSE"];
	}
	
	CaseLog_WriteMessage(caseLog_compression);

	for (i = 0; i < [collectionModules count]; i++)
	{	
		if (!acquisitionInProgress)
		{
			cancelledAcquisition = YES;
			LogDebugObjc(@"Acquisition cancelled...\n");
			break;
		}
		

		LogDebugObjc(@"Getting module...\n");
		
		CollectionModule *currentModule = [collectionModules objectAtIndex:i];
		
		if (![currentModule moduleEnabled])
		{
			[currentModule setModuleStatus:COLLECTIONMODULE_STATUS_ACQUISITION_SKIPPED];
			continue;
		}
		
		LogDebugObjc(@"Creating inner pool...\n");
		
		NSAutoreleasePool *innerPool = [[NSAutoreleasePool alloc] init];		
		
		LogDebugObjc(@"Performing acquisition for module: %@\n", [currentModule moduleShortName]);
        
        caseLogMessage = [NSString stringWithFormat:@"%@ - Acquisition Started: %@", [currentModule moduleShortName], [[NSDate date] description] ];
        CaseLog_WriteMessage(caseLogMessage);
				
		[self performSelectorOnMainThread:@selector(updateProgressText:) withObject:[[currentModule moduleName] copy] waitUntilDone:YES];

		currentlyRunningModule = currentModule;
		
		@try 
		{
			[currentModule acquisitionStart:[self casePathString] withCompression:[optionEnableCompression state]];
		}
		@catch (NSException *e)
		{
			collectionmodule_status_t status;
			
			if ([[e name] isEqualToString:NSFileHandleOperationException])
			{
				status = COLLECTIONMODULE_STATUS_ERROR_LOW_DISK_SPACE;
			}
			else 
			{
                LogDebugObjc(@"Exception Caught: %@\n", [e name]);
				status = COLLECTIONMODULE_STATUS_ERROR;
			}
			
			[currentModule setModuleStatus:status];
			
			// updateModuleProgress will update from main thread
			[AppController updateModuleProgress:100.0];
		}
		
        caseLogMessage = [NSString stringWithFormat:@"%@ - Acquisition Ended: %@", [currentModule moduleShortName], [[NSDate date] description] ];
        CaseLog_WriteMessage(caseLogMessage);
        
		[self performSelectorOnMainThread:@selector(refreshTableView) withObject:nil waitUntilDone:NO];
		
		LogDebugObjc(@"Module Acquisition complete\n");
						
		// reset object in case gui told it to cancel
		[currentModule setCancelAcquisition:FALSE];

		LogDebugObjc(@"draining pool... ");
		
		[innerPool drain];
		
		LogDebugObjc(@"Done!\n");
	}
	
	caseLogMessage = [NSString stringWithFormat:@"Acquisition Complete: %@", [[NSDate date] description] ];
    CaseLog_WriteMessage(caseLogMessage);
    
    currentlyRunningModule = nil;
	
	[CaseLog close];	
	
	if (cancelledAcquisition)
	{
		[self performSelectorOnMainThread:@selector(updateProgressText:) withObject:@"Acquisition Cancelled!" waitUntilDone:YES];
		LogDebugObjc(@"Acquisition Cancelled!\n");
	}
	else
	{
		[self performSelectorOnMainThread:@selector(updateProgressText:) withObject:@"Acquisition Complete!" waitUntilDone:YES];
		LogDebugObjc(@"Acquisition Complete!\n");
	}
	
	[self performSelectorOnMainThread:@selector(finishedAcquisition) withObject:nil waitUntilDone:YES];

	LogDebugObjc(@"Finished... draining pool\n");
	
	[pool drain];
}

- (BOOL)verifyInputs
{
	BOOL errorFlag = NO;
	NSString *errorString = @"";
	
	if ([[examinerName stringValue] isEqualToString:@""])
	{
		errorFlag = YES;
		LogDebugObjc(@"Error: Examiner Name not specified!\n");
		errorString = [errorString stringByAppendingFormat:@"*Examiner Name not specified!\n"];
	}

	if ([[caseIdentifier stringValue] isEqualToString:@""])
	{
		errorFlag = YES;
		LogDebugObjc(@"Error: Case Identifier not specified!\n");
		errorString = [errorString stringByAppendingFormat:@"*Case Identifier not specified!\n"];
	}
	
	if ([[caseCurrentDateTime stringValue] isEqualToString:@""])
	{
		errorFlag = YES;
		LogDebugObjc(@"Error: Current Date & Time not specified!\n");
		errorString = [errorString stringByAppendingFormat:@"*Current Date & Time not specified!\n"];
	}
	
#if 0 // require case notes?
	if ([[caseNotes stringValue] isEqualToString:@""])
	{
		errorFlag = YES;
		LogDebugObjc(@"Error: Case Notes not specified!\n");
		errorString = [errorString stringByAppendingFormat:@"*Case Notes not specified!\n"];
	}
#endif	
		
	BOOL isDir;
	BOOL exists;
	
	// check to see if base path is legit
	exists = [fileManager fileExistsAtPath:baseOutputString isDirectory:&isDir];
	
	if (!exists)
	{
		// error
		errorFlag = YES;		
		LogDebugObjc(@"Error: Specified output directory is invalid (does not exist!)\n");
		errorString = [errorString stringByAppendingFormat:@"*Specified output directory is invalid (does not exist!)\n"];

	}
	else if ([self checkCasePathExists:&isDir])
	{
		errorFlag = YES;		
		if (isDir)
		{
			LogDebugObjc(@"Error: Case Directory Invalid (Directory already exists with same name)!\n");
			errorString = [errorString stringByAppendingFormat:@"*Case Directory Invalid (Directory already exists with same name)!\n"];
		}
		else 
		{
			LogDebugObjc(@"Error: Case Directory Invalid (File already exists with same name)!\n");
			errorString = [errorString stringByAppendingFormat:@"*Case Directory Invalid (File already exists with same name)!\n"];
		}
	}

	if (errorFlag)
	{
			[self alertUser:errorString];
	}
	
	//[errorString release];
		
	return !errorFlag;
}

- (void)startAcquisition:(id)sender
{
	if (acquisitionInProgress)
	{
		return;
	}
	
	acquisitionInProgress = YES;
	
	LogDebugObjc(@"startAcquisition...\n");	
	
	if (![self verifyInputs])
	{
		acquisitionInProgress = NO;
		return;
	}
	
	@try 
	{
		if (![fileManager createDirectoryAtPath:[self casePathString] withIntermediateDirectories:YES attributes:nil error:nil])
		{
			[self alertUser:@"*Unable to create to case directory (insufficient permissions?"];
			acquisitionInProgress = NO;
			return;
		}
	}
	@catch (NSException *e)
	{
		[self alertUser:@"Unable to create case directory (low disk space)"];
		acquisitionInProgress = NO;
		return;
	}
	
	/* paranoid: double check the directory exists */
	BOOL isDir;
	BOOL exists;
	
	exists = [fileManager fileExistsAtPath:[self casePathString] isDirectory:&isDir];
	
	if (!exists || !isDir)
	{
		[self alertUser:@"*Paranoid check for case directory's existence failed!\n"]; 
		acquisitionInProgress = NO;
		return;
	}
	
	//if ([Utility getOSXVersion] >= OSX_Version_10_6)
	//{
	//	[tableView setSelectionHighlightStyle:NSTableViewSelectionHighlightStyleNone];
	//} else {
	[tableView deselectAll:nil];
	//}

	[tableView setEnabled:NO];
	[examinerName setEnabled:NO];
	[caseIdentifier setEnabled:NO];
	[caseCurrentDateTime setEnabled:NO];
	[caseNotes setEditable:NO];	
	[startButton setEnabled:NO];
	[optionEnableCompression setEnabled:NO];
	[optionEnableDebugLogging setEnabled:NO];
	[outputPathControl setEnabled:NO];
	[enableDisableAllButton setEnabled:NO];
	[stopButton setEnabled:YES];
	[progressIndicatorText setEnabled:YES];
	
	[self performSelectorInBackground:@selector(acquisitionThread) withObject:nil];
}

- (void)stopAcquisition:(id)sender
{
	LogDebugObjc(@"cancelAcquisition...\n");
	
	if (!acquisitionInProgress)
	{
		return;
	}
	
	acquisitionInProgress = NO;
	
	[stopButton setEnabled:NO];
	
	// since we are running in a different thread, we save our own copy to ensure there is no race condition
	CollectionModule *collectionModule = currentlyRunningModule;

	if (collectionModule)
	{
		[collectionModule setCancelAcquisition:TRUE];
	}
}

- (void)debugButton:(id)sender
{
	LogDebugObjc(@"debugButton...\n");
	LogDebugObjc(@"progressIndicatorText: %@\n", [progressIndicatorText stringValue]);
	[progressIndicatorText setStringValue:[progressIndicatorText stringValue]];
}

@end
