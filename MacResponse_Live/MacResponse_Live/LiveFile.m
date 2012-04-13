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
#import "Objective-Zip/ZipWriteStream.h"

#import "LiveFile.h"
#import "LiveLog.h"
#import "Utility.h"
#import "CaseLog.h"
#include <sys/types.h>
#include <sys/stat.h>

@implementation LiveFile

@synthesize filePath, writeableFile, appendEnabled, compressionEnabled, fileHandle, zipFileObject, zipWriteStream;

- (LiveFile *)init
{
	self = [super init];
	
	inputDataHashSHA256 = nil;
	outputDataHashSHA256 = nil;
	filePath = nil;
	fileHandle = nil;
	
	CC_SHA256_Init(&inputHashCtx);
	CC_SHA256_Init(&outputHashCtx);
    
    zipFileObject = nil;
    
	return self;
}

+ (LiveFile *)allocLiveFileRead:(NSString *)path
{
	LiveFile *lf = [[LiveFile alloc] init];
	
	[lf setFilePath:path];
	[lf setWriteableFile:FALSE];
	[lf setCompressionEnabled:FALSE];
	[lf setAppendEnabled:FALSE];
	
	// open file
	[lf setFileHandle:[NSFileHandle fileHandleForReadingAtPath:path]];
	
	if ([lf fileHandle] == nil) 
	{
		[lf release];
		LogDebugObjc(@"Unable to open file for writing!\n");
		return nil;
	}
	
	NSString *caseLog_openRead = [NSString stringWithFormat:@"Opened file for reading: %@", path];
	CaseLog_WriteMessage(caseLog_openRead);
			
	return lf;
}

+ (LiveFile *)allocLiveFileCreate:(NSString *)path withCompression:(Boolean)compressed
{
	LiveFile *lf = [[LiveFile alloc] init];
	
    [lf setWriteableFile:TRUE];
	[lf setCompressionEnabled:compressed];
	[lf setAppendEnabled:FALSE];
    [lf setFilePath:path];
    
	if (compressed)
	{
        // TODO: error check
		[lf setFilePath:[path stringByAppendingFormat:@".zip"]];
        ZipFile *zf = [[ZipFile alloc]initWithFileName:[lf filePath] mode:ZipFileModeCreate];
        [lf setZipFileObject:zf];
        ZipWriteStream *zws = [[lf zipFileObject] writeFileInZipWithName:[path lastPathComponent] fileDate:[NSDate date] compressionLevel:ZipCompressionLevelDefault];
        [lf setZipWriteStream:zws];        
	}
    else
    {
        [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
        NSFileHandle *output = [NSFileHandle fileHandleForWritingAtPath:path];
        [lf setFileHandle:output];
    }
    
	if (![path hasSuffix:@"CaseLog.xml"])
	{
		NSString *caseLog_create = [NSString stringWithFormat:@"Created file: %@", [lf filePath]];
		CaseLog_WriteMessage(caseLog_create);
	}
	
	return lf;
}

- (Boolean)handleWritingCompressedData:(NSData *)data
{	
    [zipWriteStream writeData:data];
   
	return TRUE;
}

- (Boolean)finishWritingCompressedData
{	    
    [zipWriteStream finishedWriting];
    [self setZipWriteStream: nil];
    [zipFileObject close];
    [self setZipFileObject: nil];
	return TRUE;
}

- (Boolean)write:(NSData *)data
{
	if (!writeableFile)
	{
		LogDebugObjc(@"BUG: Attempted to write to read-only file descriptor: %@!\n", filePath);
		return FALSE;
	}
	
	//LogObjc(@"%@: write 0x%llx bytes of data starting at offset 0x%llx\n", filePath, [data length], [self offset]);
	
	CC_SHA256_Update(&inputHashCtx, [data bytes], (unsigned int)[data length]);
	
	if (compressionEnabled) 
	{
		return [self handleWritingCompressedData:data];
	}
	else 
	{
        if (fileHandle == nil)
        {
            LogDebugObjc(@"Failed to write to file: %@", filePath);
            return FALSE;
        }
        
		[fileHandle writeData: data];	
	}
	
	return TRUE;
}


- (NSData *)read // reads file in one operation...
{
	NSData *data = [fileHandle readDataToEndOfFile];
	inputDataHashSHA256 = [Utility hashDataSHA256:data];
	return data;
}	

- (NSData *)readBytes:(UInt64)numBytes // reads partial file
{
	NSData *data = [fileHandle readDataOfLength:(unsigned int)numBytes];
	CC_SHA256_Update(&inputHashCtx, [data bytes], (unsigned int)[data length]);
	return data;
}

- (UInt64)size
{
	unsigned long long currentOffset = [self offset];
	unsigned long long eofOffset = [[self fileHandle] seekToEndOfFile];
	
	[[self fileHandle] seekToFileOffset:currentOffset];
	
	return eofOffset;
}

- (UInt64)offset // returns current file offset
{
	return (UInt64) [fileHandle offsetInFile];
}

- (Boolean)close
{
	uint8_t digest[CC_SHA256_DIGEST_LENGTH];

	// check to make sure reads have finished reading....
	if (writeableFile == FALSE && [self size] != [self offset]) 
    {
		// TODO: we have a case where we read a file without finishing reading it
		// CASE LOG THIS
		LogDebugObjc(@"File opened for read, but not done reading!! 0x%llx 0x%llx\n", [self offset], [self size]);
	}
	
	if (writeableFile && compressionEnabled) 
	{
		[self finishWritingCompressedData]; 
	}
	
    if ([self fileHandle])
    {
        [fileHandle closeFile];
        [self setFileHandle:nil];	
    }
		
	CC_SHA256_Final(digest, &inputHashCtx);
	NSData *digestData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
	inputDataHashSHA256 = [Utility dataToHexString:digestData];		
	
	if (![[self filePath] hasSuffix:@"CaseLog.xml"])
	{
		NSString *caseLog_close = [NSString stringWithFormat:@"Closed file: %@", [self filePath]];
		CaseLog_WriteMessage(caseLog_close);
		
		// if the file was open for read-only, no need to log the hash values
		if (writeableFile)
		{
			NSString *caseLog_inputHash = [NSString stringWithFormat:@"Uncompressed Data SHA-256: %@", [self inputDataHashSHA256]];
			CaseLog_WriteMessage(caseLog_inputHash);
		}
	}
	
	return TRUE;
}

- (NSString *)outputDataHashSHA256 // file required to be read-only or closed if writeable - else nil - returns hash of file output data stream
{
	if (!writeableFile) 
	{
		// read-only file - no output data hash
		return nil;
	}
	
	if (!compressionEnabled) 
	{
		// input is same as output
		return inputDataHashSHA256;
	}
	
	return outputDataHashSHA256;
}

- (NSString *)inputDataHashSHA256 // sha256 hash of the input data - if compression was enabled, this is different from the output file hash
{
	return inputDataHashSHA256;
}

+ (Boolean)setFileReadOnly:(NSString *)path
{ 
	// could use NSFileManager attributesOfItemAtPath:error/setAttributes:ofItemAtPath:error: available since 10.5
#ifdef SUPPORT_10_4
	if (chmod([path UTF8String], S_IRUSR | S_IRGRP | S_IROTH) == 0) {
		return TRUE;
	}
	return FALSE;
#else
	NSDictionary *dict = [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedLong:0444]
													 forKey:NSFilePosixPermissions];
	NSError *error = nil;
	
	[[NSFileManager defaultManager] setAttributes:dict ofItemAtPath:path error:&error];
	
	if (error) 
	{
		LogDebugObjc(@"error setting file to readonly: %@\n", path);
		LogDebugObjc(@"localizedDescription = %@\n", [error localizedDescription]);
		LogDebugObjc(@"localizedFailureReason = %@\n", [error localizedFailureReason]);
		return FALSE;
	}
	
	NSString *caseLog_setPerm = [NSString stringWithFormat:@"Set file read only: %@", path];
	CaseLog_WriteMessage(caseLog_setPerm);
	
	return TRUE;
#endif
}

#define MAX_SINGLE_READ_BLOCKSIZE (1024 * 1024) // 1 MB
#define TYPICAL_READ_BLOCKSIZE (64 * 1024) // 64KB

+ (Boolean)copyFile:(NSString *)srcPath toPath:(NSString *)dstPath withCompression:(Boolean)useCompression // copy single file (static function using LiveFiles)
{
	NSString *caseLog_copy = [NSString stringWithFormat:@"Copying file from %@ to %@", srcPath, dstPath];
	CaseLog_WriteMessage(caseLog_copy);
	
	UInt64 i, fileLength = 0;
	LiveFile *src = [LiveFile allocLiveFileRead:srcPath];
	
	if (src == nil)
	{
		LogDebugObjc(@"source file missing!\n");
		return FALSE;
	}
	
	LiveFile *dst = [LiveFile allocLiveFileCreate:dstPath withCompression:useCompression];
	
	if (dst == nil)
	{
		LogDebugObjc(@"unable to open dest file!\n");
		[src release];
		return FALSE;
	}
	
	fileLength = [src size];
	
	if ([src size] > MAX_SINGLE_READ_BLOCKSIZE) 
	{
		for (i = 0; i < fileLength; i += TYPICAL_READ_BLOCKSIZE) 
		{
			NSData *data = [src readBytes:TYPICAL_READ_BLOCKSIZE];
			[dst write:data];
		}
	}
	else 
	{
		NSData *data = [src read];
		[dst write:data];
	}
	
	[src close];
	[dst close];
	
	[src release];
	[dst release];
	
	return TRUE;
}

+ (Boolean)copyPlistFile:(NSString *)srcPath toPath:(NSString *)dstPath
{
	NSString *caseLog_CopyPList = [NSString stringWithFormat:@"Copying property list file %@ to %@", srcPath, dstPath];
	CaseLog_WriteMessage(caseLog_CopyPList);
	
	//NOTE: Doing a normal copyFile in this case would not work because some of the property list files may
	// be stored in binary mode (rather than text mode).  These binary files will not necessarily be
	// viewable on the analysts machine, depending on the operating system used.  To get around this issue,
	// we are reading the plist files into a dictionary, and writing the data back out to a file, via 
	// the objective C NSDictionary call 'writeToFile'.
	//
	// However, at the moment, we cannot currently take advantage of the functions above for compressing
	// the data as it is being written.  These files may need to be individually compressed after they are 
	// closed... more to come.
	
	NSDictionary *plistDict = [[NSDictionary alloc] initWithContentsOfFile:srcPath];
	[plistDict writeToFile:dstPath atomically:YES];
	[plistDict release];
	
	NSString *caseLog_hash = [NSString stringWithFormat:@"Uncompressed Data Hash: %@", [LiveFile hashFile:dstPath]];
	CaseLog_WriteMessage(caseLog_hash);
	
	return TRUE;
}

+ (Boolean)copyDirectory:(NSString *)srcPath toPath:(NSString *)dstPath withCasePath:(NSString *)casePath withCompression:(Boolean)useCompression // recursive directory copy (static function using LiveFiles)
{
    //First, check to see if the srcPath matches the casePath, if so, DON'T attempt to copy it
    
    // srcPath does not have a trailing '/', while casePath does
    NSString *tempSrcPath = [srcPath stringByAppendingFormat:@"/"];
    if ((casePath) && ([tempSrcPath isEqualToString:casePath]))
    {
        LogDebugObjc(@"copy directory... skipping case path\n");
        return TRUE;
    }
    
	NSError  *error = nil;
	NSFileManager *manager = [NSFileManager defaultManager];
	NSArray *files = [manager contentsOfDirectoryAtPath:srcPath error:&error];

	if (error) 
	{
		LogDebugObjc(@"error copying directory %@\n", srcPath, dstPath);
		LogDebugObjc(@"localizedDescription = %@\n", [error localizedDescription]);
		LogDebugObjc(@"localizedFailureReason = %@\n", [error localizedFailureReason]);
		return FALSE;
	}
	
	[manager createDirectoryAtPath:dstPath withIntermediateDirectories:YES attributes:nil error:&error];
	if (error)
	{
		LogDebugObjc(@"Error creating directory %@\n", dstPath);
		LogDebugObjc(@"ERROR: %@\n", error);
		return FALSE;
	}
	
	for (NSString *file in files)
	{
		NSString *srcSubPath = [srcPath stringByAppendingPathComponent:file];
		NSString *dstSubPath = [dstPath stringByAppendingPathComponent:file];
		
		BOOL isDir;
		
		if (![manager fileExistsAtPath:srcSubPath isDirectory:&isDir]) 
		{
			continue;
		}
		
		NSString *symPath = [manager destinationOfSymbolicLinkAtPath:srcSubPath error:NULL];
		// symPath will be NULL if srcSubPath is not a symbolic link
		if (symPath)
		{
			continue;
		}
		
		if (isDir) 
		{
			// recurse into the lower depths
			[manager createDirectoryAtPath:dstSubPath withIntermediateDirectories:NO attributes:nil error:&error];
			if (error)
			{
				LogDebugObjc(@"Error creating directory %@\n", dstSubPath);
				LogDebugObjc(@"ERROR: %@\n", error);
				return FALSE;
			}
			
			NSString *caseLog_createDir = [NSString stringWithFormat:@"Created directory: %@", dstSubPath];
			CaseLog_WriteMessage(caseLog_createDir);
			
			[LiveFile copyDirectory:srcSubPath toPath:dstSubPath withCasePath:casePath withCompression:useCompression];
		}
		else 
		{
			[LiveFile copyFile:srcSubPath toPath:dstSubPath withCompression:useCompression];
		}
	}
	
	return TRUE;
}

+ (NSString *)hashFile:(NSString *)path
{
	NSData *data = [NSData dataWithContentsOfFile:path];
	return [Utility hashDataSHA256:data];
}

@end
