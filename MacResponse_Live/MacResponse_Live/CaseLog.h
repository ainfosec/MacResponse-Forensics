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
#import "LiveXML.h"

@interface CaseLog : NSObject {
	LiveXML *caseLogXML;
	NSString *caseLogPath;
}

- (Boolean)open:(NSString *)filePath;

- (Boolean)writeLogSimple:(NSString *)message;

- (Boolean)writeLog:(NSString *)message fromFile:(NSString *)file fromFunction:(NSString *)fn fromLine:(int)line;

- (void)close;

/** STATIC FUNCTIONS TO BE USED BY MODULES **/
+ (Boolean)initCaseLog:(NSString *)casePath;

+ (CaseLog *)caseLog;

+ (void)close;

#define CaseLog_WriteMessage(message) ([[CaseLog caseLog] writeLog:message fromFile:[NSString stringWithUTF8String:__FILE__] fromFunction:[NSString stringWithUTF8String:__FUNCTION__] fromLine:__LINE__])

@end
