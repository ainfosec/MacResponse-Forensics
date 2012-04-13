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

#ifndef _LIVELOG_H_
#define _LIVELOG_H_

#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define DEBUG 1

// NSString * log (no format interpretation)
#define LogObjcString(str) LiveLog_LogObjcString(__FILE__, __FUNCTION__, __LINE__, str)

// NSString * based logs
#define LogObjc(fmt, ...) LiveLog_LogObjc(__FILE__, __FUNCTION__, __LINE__, fmt, ## __VA_ARGS__)

// C strings (ASCII/UTF8) based logs
#define LogUtf8(fmt, ...) LiveLog_LogUtf8(__FILE__, __FUNCTION__, __LINE__, fmt, ## __VA_ARGS__)

// Debugging only logs
#ifdef DEBUG

#define LogDebugObjc(fmt, ...) LogObjc(fmt, ## __VA_ARGS__)
#define LogDebugUtf8(fmt, ...) LogUtf8(fmt, ## __VA_ARGS__)

#else

#define LogDebugObjc(fmt, ...)
#define LogDebugUtf8(fmt, ...)

#endif

void LiveLog_LogObjc(const char *file, const char *func, int line, NSString *fmt, ...);
void LiveLog_LogUtf8String(const char *file, const char *func, int line, const char *str);
void LiveLog_LogUtf8(const char *file, const char *func, int line, const char *fmt, ...);

@interface LiveLog : NSObject {
	
}

@end

#endif /* _LIVELOG_H_ */
