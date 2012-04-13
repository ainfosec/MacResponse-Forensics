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

@implementation LiveLog

@end

#ifdef DEBUG

static FILE *debugFileHandle = NULL;

void
LiveLog_DebugFileHandleInit(void)
{
	if (debugFileHandle)
	{
		return;
	}
	
	debugFileHandle = fopen("/tmp/macresponse.log", "a");
}

#endif // DEBUG

void 
LiveLog_LogUtf8String(const char *file, const char *func, int line, const char *str)
{
#ifdef DEBUG
	fprintf(stdout, "%s(%d):\t%s", func, line, str);
	fflush(stdout);
	
	LiveLog_DebugFileHandleInit();

	if (debugFileHandle)
	{
		fprintf(debugFileHandle, "%s(%d):\t%s", func, line, str);
		fflush(debugFileHandle);
	}
	else {
		NSLog(@"failed to open log file\n");
	}

	//NSLog(@"[%s:%d] %s", file, line, str);
#else
	fprintf(stdout, "%s", str);
	fflush(stdout);
	//NSLog(@"%s", str);
#endif
}

void
LiveLog_LogUtf8(const char *file, const char *func, int line, const char *fmt, ...)
{
	char *p = NULL;
	int ret __attribute__((unused));
	
	va_list ap;
	
	va_start(ap, fmt);
	ret = vasprintf(&p, fmt, ap);	
	va_end(ap);
	
	LiveLog_LogUtf8String(file, func, line, p);
}

void
LiveLog_LogObjc(const char *file, const char *func, int lineNumber, NSString *fmt, ...)
{
	const char *p;
	va_list ap;
    
	va_start (ap, fmt);
	
    NSString *result =  [[NSString alloc] initWithFormat: fmt arguments: ap];
    
	va_end (ap);
    
	p = [result UTF8String];
	
	LiveLog_LogUtf8String(file, func, lineNumber, p);
	
    [result release];
}
