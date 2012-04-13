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
#import "LiveLog.h"
#import "Utility.h"

int main(int argc, char *argv[])
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	
	int ret;
	
	char * appArgs[2];
	appArgs[0] = "-nosudo";
	appArgs[1] = NULL;
    
	int i;
	
	for (i = 0; i < argc; i++)
	{
		LogObjc(@"argument %d: %s\n", i, argv[i]);
	}
	
	int euid = geteuid();
	int uid = getuid();
	
	LogObjc(@"euid: 0x%x\n", euid);
	LogObjc(@"uid: 0x%x\n", uid);
    
	NSString *path = [[NSBundle mainBundle] bundlePath];
    
	path = [NSString stringWithFormat:@"%@%@", path, @"/Contents/MacOS/MacResponse_Live"];
    
	const char *appPath = [path UTF8String];
	
	LogObjc(@"appPath = %s\n", appPath);
	
	if (argc > 2 && strcmp(argv[1], "-nosudo") == 0)
	{
		// we are executed for the second time - we run regardless now
	}
	else 
	{
		// first run, lets attempt sudo if we are not root
		if (euid != 0)
		{
			LogObjc(@"Asking for administrator credentials...\n");
			if ([Utility executeWithRoot:appPath withArgs:appArgs withFilePipe:NULL])
			{
				LogObjc(@"Successfully spawned self as root... exiting.\n");
				[pool drain];
				exit(0);
			}			
		}
	}
	
	ret = NSApplicationMain(argc,  (const char **) argv);
	[pool drain];
	return ret;
}
