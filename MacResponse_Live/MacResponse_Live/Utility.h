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

typedef enum {
	OSX_Version_Unsupported = 0,
	OSX_Version_10_5,
	OSX_Version_10_6,
	OSX_Version_10_7
} osx_version_t;

typedef enum {
	OSX_Kernel_Arch_Unsupported = 0,
	OSX_Kernel_Arch_i386,
	OSX_Kernel_Arch_x86_64,
} osx_kernel_arch_t;

@interface Utility : NSObject {
	
}

+ (Boolean)executeWithRoot:(const char *)path withArgs:(char * const *)args withFilePipe:(FILE **)stdInOutHandle;
+ (NSString *)dataToHexString:(NSData *)data;
+ (NSString *)hashDataSHA256:(NSData *)data;
+ (NSData *)gzipInflate:(NSData *)data;
+ (NSData *)gzipDeflate:(NSData *)data;
+ (NSNumber *)getFileSystemFreeSpace:(NSString *)path;
+ (NSString *)generateRandomTempDirectory;
+ (NSNumber *)getDirectorySize:(NSString *)dirPath;
+ (NSNumber *)getPhysicalMemorySize;
+ (osx_version_t)getOSXVersion;
+ (osx_kernel_arch_t)getOSXKernelArch;

@end

//BOOL Utility_Sudo(const char *path, char * const *args);
