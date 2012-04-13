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
#include <CommonCrypto/CommonDigest.h>
#import "Objective-Zip/ZipFile.h"
#import "Objective-Zip/ZipWriteStream.h"

@interface LiveFile : NSObject {
	NSString *filePath;
	Boolean writeableFile;
	Boolean appendEnabled; // make sure to check this when generating a hash
	Boolean compressionEnabled;
	NSFileHandle *fileHandle;
	CC_SHA256_CTX inputHashCtx;
	CC_SHA256_CTX outputHashCtx;
	NSString *inputDataHashSHA256;
	NSString *outputDataHashSHA256;
	UInt64 fileSize;
	
    ZipFile *zipFileObject;
    ZipWriteStream *zipWriteStream;
}

// Open file for reading
+ (LiveFile *)allocLiveFileRead:(NSString *)path;

// Create file for writing
+ (LiveFile *)allocLiveFileCreate:(NSString *)path withCompression:(Boolean)compressed;

- (Boolean)write:(NSData *)data;

- (NSData *)read; // reads file in one operation...

- (NSData *)readBytes:(UInt64)numBytes; // reads partial file

- (UInt64)offset; // returns current file offset

- (Boolean)close;

- (NSString *)outputDataHashSHA256; // file required to be read-only or closed if writeable - else nil - returns hash of file output data stream

- (NSString *)inputDataHashSHA256; // sha256 hash of the input data - if compression was enabled, this is different from the output file hash

+ (Boolean)setFileReadOnly:(NSString *)path;

+ (Boolean)copyFile:(NSString *)srcPath toPath:(NSString *)dstPath withCompression:(Boolean)useCompression; // copy single file (static function using LiveFiles)

+ (Boolean)copyPlistFile:(NSString *)srcPath toPath:(NSString *)dstPath; // copy single Property List file

+ (Boolean)copyDirectory:(NSString *)srcPath toPath:(NSString *)dstPath withCasePath:(NSString *)casePath withCompression:(Boolean)useCompression; // recursive directory copy (static function using LiveFiles)

+ (NSString *)hashFile:(NSString *)path;

@property (readwrite, copy) NSString *filePath;
@property (readwrite, assign) Boolean writeableFile;
@property (readwrite, assign) Boolean appendEnabled;
@property (readwrite, assign) Boolean compressionEnabled;
@property (readwrite, retain) NSFileHandle *fileHandle;
@property (readwrite, retain) ZipFile *zipFileObject;
@property (readwrite, retain) ZipWriteStream *zipWriteStream;
@end
