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

#import "Objective-Zip/ZipFile.h"
#import "Utility.h"
#import "LiveLog.h"
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/sysctl.h>


@implementation Utility

+ (Boolean)executeWithRoot:(const char *)path withArgs:(char * const *)args withFilePipe:(FILE **)stdInOutHandle;
{
	AuthorizationRef auth = NULL;
	OSStatus err;
	
	err = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagInteractionAllowed, &auth);
	
	if (err != errAuthorizationSuccess) {
		LogDebugObjc(@"AuthorizationCreate failed with: %d %s (%s)\n",
					 (unsigned int) err, GetMacOSStatusErrorString(err), GetMacOSStatusCommentString(err));
		return FALSE;
	}
	
	err = AuthorizationExecuteWithPrivileges(auth, path, kAuthorizationFlagDefaults, args, stdInOutHandle);
	
	if (err != errAuthorizationSuccess) {
		LogDebugObjc(@"AuthorizationExecuteWithPrivileges failed with: %d %s (%s)\n",
				(unsigned int) err, GetMacOSStatusErrorString(err), GetMacOSStatusCommentString(err));
		return FALSE;
	}
	
	return TRUE;
}

+ (NSString *)dataToHexString:(NSData *)data
{
    NSMutableString *hex = [NSMutableString string];
    unsigned char *bytes = (unsigned char *)[data bytes];
    char temp[3];
    int i = 0;
    for (i = 0; i < [data length]; i++) {
        temp[0] = temp[1] = temp[2] = 0;
        (void)snprintf(temp, sizeof(temp), "%02x", bytes[i]);
        [hex appendString:[NSString stringWithUTF8String: temp]];
    }
    return hex;
}	

+ (NSString *)hashDataSHA256:(NSData *)data
{
	uint8_t digest[CC_SHA256_DIGEST_LENGTH]={0};
	
	CC_SHA256([data bytes], (unsigned int)[data length], digest);
	
	NSData *digestData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
	
	return [Utility dataToHexString:digestData];
}

+ (NSData *)gzipInflate:(NSData *)data
{
	if ([data length] == 0) return data;
	
	unsigned long full_length = [data length];
	unsigned long half_length = [data length] / 2;
	
	NSMutableData *decompressed = [NSMutableData dataWithLength: full_length + half_length];
	BOOL done = NO;
	int status;
	
	z_stream strm;
	strm.next_in = (Bytef *)[data bytes];
	strm.avail_in = (int)[data length];
	strm.total_out = 0;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	
	if (inflateInit2(&strm, (15+32)) != Z_OK) return nil;
	while (!done)
	{
		// Make sure we have enough room and reset the lengths.
		if (strm.total_out >= [decompressed length])
			[decompressed increaseLengthBy: half_length];
		strm.next_out = [decompressed mutableBytes] + strm.total_out;
		strm.avail_out = (unsigned int)[decompressed length] - (unsigned int)strm.total_out;
		
		// Inflate another chunk.
		status = inflate (&strm, Z_SYNC_FLUSH);
		if (status == Z_STREAM_END) done = YES;
		else if (status != Z_OK) break;
	}
	if (inflateEnd (&strm) != Z_OK) return nil;
	
	// Set real length.
	if (done)
	{
		[decompressed setLength: strm.total_out];
		return [NSData dataWithData: decompressed];
	}
	else return nil;
}

+ (NSData *)gzipDeflate:(NSData *)data
{
	if ([data length] == 0) return data;
	
	z_stream strm;
	
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.total_out = 0;
	strm.next_in=(Bytef *)[data bytes];
	strm.avail_in = (unsigned int)[data length];
	
	// Compresssion Levels:
	//   Z_NO_COMPRESSION
	//   Z_BEST_SPEED
	//   Z_BEST_COMPRESSION
	//   Z_DEFAULT_COMPRESSION
	
	if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, (15+16), 8, Z_DEFAULT_STRATEGY) != Z_OK) return nil;
	
	NSMutableData *compressed = [NSMutableData dataWithLength:16384];  // 16K chunks for expansion
	
	do {
		
		if (strm.total_out >= [compressed length])
			[compressed increaseLengthBy: 16384];
		
		strm.next_out = [compressed mutableBytes] + strm.total_out;
		strm.avail_out = (unsigned int)[compressed length] - (unsigned int)strm.total_out;
		
		deflate(&strm, Z_FINISH);  
		
	} while (strm.avail_out == 0);
	
	deflateEnd(&strm);
	
	[compressed setLength: strm.total_out];
	return [NSData dataWithData:compressed];
}

+ (NSNumber *)getFileSystemFreeSpace:(NSString *)path
{
	NSNumber *freeSpace = 0;
	NSError *error = nil;
	NSDictionary *attr = [[NSFileManager defaultManager] attributesOfFileSystemForPath:path error:&error];
	if (!error)
	{
		freeSpace = [attr objectForKey:NSFileSystemFreeSize];
	}
	
	return freeSpace;
}

+ (NSNumber *)getDirectorySize:(NSString *)dirPath
{
	NSString *size;
	NSPipe *pipe = [NSPipe pipe];
	NSTask *task = [[NSTask alloc] init];
	[task setLaunchPath:@"/usr/bin/du"];
	[task setArguments:[NSArray arrayWithObjects:@"-d", @"0", dirPath, nil]];
	[task setStandardOutput:pipe];
	[task setStandardError:[NSPipe pipe]];
	
	[task launch];
	[task waitUntilExit];
	[task release];
	
	NSString *sizeString = [[[NSString alloc] initWithData:[[pipe fileHandleForReading] availableData] encoding:NSASCIIStringEncoding] autorelease];
	sizeString = [sizeString stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@" "]];
	size = [[sizeString componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@" \t"]] objectAtIndex:0];
	
	NSNumber *sizeNumber = [NSNumber numberWithLongLong:[size longLongValue]];
	LogDebugObjc(@"SIZE: %@\n", sizeNumber);
	
	return sizeNumber;
}

+ (NSString *)generateRandomTempDirectory
{
	NSString *date = [[NSDate date] descriptionWithCalendarFormat:@"%H%M%S_%Y%m%d" timeZone:nil locale:nil];
	NSString *tempDir = [NSString stringWithFormat:@"/tmp/%@/", date];
		
	if (!([[NSFileManager defaultManager] fileExistsAtPath:tempDir]))
	{	
		NSError *error = nil;
		[[NSFileManager defaultManager] createDirectoryAtPath:tempDir withIntermediateDirectories:NO attributes:nil error:&error];
			
		if (error)
		{
			// Log error
			return NULL;
		}
		else 
		{
			return tempDir;
		}
	}
	
	return NULL;
}

+ (NSNumber *)getPhysicalMemorySize
{
	char buffer[BUFSIZ];
	int mib[2] = {CTL_HW, HW_MEMSIZE};
	
	size_t size = BUFSIZ;
	sysctl(mib, 2, buffer, &size, NULL, 0);
	
	NSString *memSize = [NSString stringWithFormat:@"%qd", *(quad_t *)buffer];
	NSNumber *memSizeNumber = [NSNumber numberWithLongLong:[memSize longLongValue]];
	
	return memSizeNumber;
}

// For now, until we upgrade to a newer version of Xcode and build against the
// 10.7 SDK, we need to define the following:
//    NSAppKitVersionNumber10_6 1038
//    NSAppKitVersionNumber10_7 1138
#define NSAppKitVersionNumber10_6   1038
#define NSAppKitVersionNumber10_7   1138
+ (osx_version_t)getOSXVersion
{
	osx_version_t version = OSX_Version_Unsupported;
    
    if (floor(NSAppKitVersionNumber) == NSAppKitVersionNumber10_7)
    {
        version = OSX_Version_10_7;
    }
	else if (floor(NSAppKitVersionNumber) == NSAppKitVersionNumber10_6)
	{
		version = OSX_Version_10_6;
	}
	else if (floor(NSAppKitVersionNumber) == NSAppKitVersionNumber10_5)
	{
		version = OSX_Version_10_5;
	}
	
	return version;
}

+ (osx_kernel_arch_t)getOSXKernelArch
{
	char buf[BUFSIZ];
	int mib[2] = {CTL_HW, HW_MACHINE};
	size_t size = BUFSIZ;
	sysctl(mib, 2, buf, &size, NULL, 0);
	
	LogDebugObjc(@"Machine: %s\n", buf);
	NSString *machine = [NSString stringWithFormat:@"%s", buf];
	
	if ([machine isEqualToString:@"i386"]) {
		return OSX_Kernel_Arch_i386;
	} else if ([machine isEqualToString:@"x86_64"]) {
		return OSX_Kernel_Arch_x86_64;
	} else {
		return OSX_Kernel_Arch_Unsupported;
	}
}

@end
