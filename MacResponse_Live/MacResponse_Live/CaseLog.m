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

#import "LiveLog.h"
#import "LiveXML.h"
#import "CaseLog.h"


@implementation CaseLog

static CaseLog *logInstance = nil;

- (id)init
{	
	return self;
}

- (Boolean)open:(NSString *)filePath
{
	LogDebugObjc(@"caselog: open... %@\n", filePath);
	if (caseLogXML != nil) {
		return FALSE;
	}

	LogDebugObjc(@"caselog: opening... %@\n", filePath);
	
	caseLogPath = filePath;
	caseLogXML = [LiveXML allocLiveXMLWith:caseLogPath];
	
	if (caseLogXML) {
		[caseLogXML insertStartTag:@"CaseLog" withLevel:0];
		[caseLogXML insertStartTag:@"logMessages" withLevel:1];
				
		LogDebugObjc(@"caselog: opening successful... %@\n", filePath);
		return TRUE;
	}
	
	LogDebugObjc(@"caselog: opening failed... %@\n", filePath);
	
	return FALSE;
}

- (Boolean)writeLogSimple:(NSString *)message
{
	LogDebugObjc(@"caselog: writeLogSimple... %@\n", message);
	
	[caseLogXML insertStartTag:@"logMessage" withLevel:2];
	
	[caseLogXML insertCompleteTag:@"message" withLevel:3 withString:message];

	[caseLogXML insertEndTag:@"logMessage" withLevel:2];	
	
	return TRUE;
}

- (Boolean)writeLog:(NSString *)message fromFile:(NSString *)file fromFunction:(NSString *)fn fromLine:(int)line
{
	LogDebugObjc(@"caselog: writeLog... %@\n", message);
	
	[caseLogXML insertStartTag:@"logMessage" withLevel:2];
	
	[caseLogXML insertCompleteTag:@"message" withLevel:3 withString:message];
	[caseLogXML insertCompleteTag:@"sourceFile" withLevel:3 withString:file];
	[caseLogXML insertCompleteTag:@"soureFunction" withLevel:3 withString:fn];
	[caseLogXML insertCompleteTag:@"sourceLine" withLevel:3 withString:[NSString stringWithFormat:@"%d", line]];
	
	[caseLogXML insertEndTag:@"logMessage" withLevel:2];
	
	return TRUE;
}

- (void)close
{
	LogDebugObjc(@"caselog: close...\n");

	if (caseLogXML) {
		[caseLogXML insertEndTag:@"logMessages" withLevel:1];
		[caseLogXML insertEndTag:@"CaseLog" withLevel:0];
		
		[caseLogXML close];
		[caseLogXML release];

		LogDebugObjc(@"caselog: closed file...\n");
	}
	
	caseLogXML = nil;
}

/** STATIC FUNCTIONS TO BE USED BY MODULES **/
+ (Boolean)initCaseLog:(NSString *)casePath
{
	LogDebugObjc(@"caselog: initCaseLog...\n");
	
	logInstance = [[CaseLog alloc] init];
	
	LogDebugObjc(@"caselog: initCaseLog %p...\n", logInstance);
	
	return [logInstance open:casePath];
}

+ (CaseLog *)caseLog
{
	LogDebugObjc(@"caselog: caseLog %p...\n", logInstance);
	
	return logInstance;
}

+ (void)close
{
	LogDebugObjc(@"caselog: closing...\n");
				 
	if (logInstance) {
		[logInstance close];
		[logInstance release];
		logInstance = nil;
	}		
}

@end
