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

#import "FilesystemInfo.h"
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

@implementation FilesystemInfo

- (id)init
{
	[super init];
	[self setModuleName: @"Fileystem (MAC Time) Information"];
	[self setModuleShortName:@"FilesystemInformation"];
	[self setModuleEnabled: FALSE];     // Disabled by default
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	return self;
}

- (unsigned int)modeToHex:(mode_t)mode
{
    unsigned int hexMode = 0;
    
    if (mode & S_ISUID)
    {
        hexMode |= 0x0004000;
    }
    
    if (mode & S_ISGID)
    {
        hexMode |= 0x0002000;
    }
    
    if (mode & S_ISVTX)
    {
        hexMode |= 0x0001000;
    }
    
    if (mode & S_IRUSR)
    {
        hexMode |= 0x400;
    }
    
    if (mode & S_IWUSR)
    {
        hexMode |= 0x200;
    }

    if (mode & S_IXUSR)
    {
        hexMode |= 0x100;
    }
    
    if (mode & S_IRGRP)
    {
        hexMode |= 0x40;
    }
    
    if (mode & S_IWGRP)
    {
        hexMode |= 0x20;
    }
    
    if (mode & S_IXGRP)
    {
        hexMode |= 0x10;
    }
    
    if (mode & S_IROTH)
    {
        hexMode |= 0x4;
    }
    
    if (mode & S_IWOTH)
    {
        hexMode |= 0x2;
    }
    
    if (mode & S_IXOTH)
    {
        hexMode |= 0x1;
    }
    
    return hexMode;
}

- (void)walkDirectoryRecursive:(NSString *)directoryPath
{
    if ([self cancelAcquisition])
    {	
        return;
    }
    
    struct dirent dp;
    struct dirent *ret;
    struct stat64 fileStat;
    
    // full path for children directories/files
    NSString *fullPath = nil;
    
    // open directory
    DIR *dir = opendir([directoryPath UTF8String]);
    
    if (dir == NULL)
    {
        LogDebugObjc(@"WARNING: error opening %@\n", directoryPath);
        return;
    }
    
    NSAutoreleasePool *innerPool = [[NSAutoreleasePool alloc] init];
    
    //LogDebugObjc(@"walkDirectory: %s\n", directoryPath);
    
    while (readdir_r(dir, &dp, &ret) == 0)
    {
        if ([self cancelAcquisition])
        {	
            [innerPool drain];
            return;
        }
        
        if (ret != &dp)
        {
            // end of directory
            break;
        }
        
        // do not append forward slash for root directory (i.e. '/','\0')
        if (!([directoryPath isEqualToString:@"/"]))
        {
            fullPath = [NSString stringWithFormat:@"%@/%s", directoryPath, dp.d_name];
        } 
        else
        {
            fullPath = [NSString stringWithFormat:@"%@%s", directoryPath, dp.d_name];
        }
        
        if (lstat64([fullPath UTF8String], &fileStat) != 0)
        {
            continue;
        }
        
        // check common case of "." and ".."
        if (S_ISDIR(fileStat.st_mode))
        {
            if (strcmp(dp.d_name, ".") == 0 ||
                strcmp(dp.d_name, "..") == 0)
            {
                continue;
            }
        }
        
        if (dp.d_type == DT_LNK)
        {
            ssize_t linkLen;
            char *linkDestPath = malloc(4096);
            
            if (linkDestPath)
            {
            
                linkLen = readlink([fullPath UTF8String], linkDestPath, 4095);
                if (linkLen > 0) 
                {
                    // readlink does not append null - we must do it ourselves
                    linkDestPath[linkLen] = 0;
                    fullPath = [NSString stringWithFormat:@"%@ -> %s", fullPath, linkDestPath];
                }
                
                free(linkDestPath);
                linkDestPath = NULL;
            }
            else
            {
                fullPath = [NSString stringWithFormat:@"%@ -> ", fullPath];
                LogDebugObjc(@"malloc failed!\n");
            }
        }

        char *fileType = "undefined";
        
        switch (dp.d_type)
        {
            case DT_UNKNOWN:
            {
                fileType = "unknown";
                break;
            }
            case DT_FIFO:
            {
                fileType = "fifo";
                break;
            }
            case DT_CHR:
            {
                fileType = "char";
                break;
            }
            case DT_DIR:
            {
                fileType = "dir";
                break;
            }
            case DT_BLK:
            {
                fileType = "block";
                break;
            }
            case DT_REG:
            {
                fileType = "regular file";
                break;
            }
            case DT_LNK:
            {
                fileType = "link";
                break;
            }
            case DT_SOCK:
            {
                fileType = "socket";
                break;
            }
            case DT_WHT:
            {
                fileType = "wht";
                break;
            }
            default:
            {
                fileType = "undefined";
                break;
            }
        }
        
        
        // there are a lot of files... we need a minimal xml output
        [self xmlInsertStartTag:@"filePathInfo" withLevel:2];
        
        [self xmlInsertCompleteTag:@"filePath" withLevel:3 withString:fullPath]; 
        
#ifdef LONG_FILE_INFO_OUTPUT
        // times must be at least 26 bytes
        char modifiedTime[26];
        char accessTime[26];
        char statusChangeTime[26];
        char birthTime[26];
        
        if (ctime_r(&fileStat.st_mtime, modifiedTime) == NULL)
        {
            strcpy(modifiedTime, "ctime_r error!\n");
        }
        
        if (ctime_r(&fileStat.st_atime, accessTime) == NULL)
        {
            strcpy(accessTime, "ctime_r error!\n");
        }
        
        if (ctime_r(&fileStat.st_ctime, statusChangeTime) == NULL)
        {
            strcpy(statusChangeTime, "ctime_r error!\n");
        }
        
        if (ctime_r(&fileStat.st_birthtime, birthTime) == NULL)
        {
            strcpy(birthTime, "ctime_r error!\n");
        }
        
        // remove newlines
        modifiedTime[24] = 0;
        accessTime[24] = 0;
        statusChangeTime[24] = 0;
        birthTime[24] = 0;
 
        //LogDebugObjc(@"file: %s\n", fullPath);
        //LogDebugObjc(@"  - modifiedTime %s\n", modifiedTime);
        //LogDebugObjc(@"  - accessTime %s\n", accessTime);
        //LogDebugObjc(@"  - statusChangeTime %s\n", statusChangeTime);
        //LogDebugObjc(@"  - birthTime %s\n", birthTime);
        
        [self xmlInsertCompleteTag:@"fileType" withLevel:3 withString:[NSString stringWithUTF8String:fileType]];
        [self xmlInsertCompleteTag:@"fileMode" withLevel:3 withString:[NSString stringWithFormat:@"%04X", [self modeToHex:fileStat.st_mode]]];
        [self xmlInsertCompleteTag:@"fileSizeBytes" withLevel:3 withString:[NSString stringWithFormat:@"%llu", (unsigned long long) fileStat.st_size]];
        [self xmlInsertCompleteTag:@"userId" withLevel:3 withString:[NSString stringWithFormat:@"%d", (int)fileStat.st_uid]];
        [self xmlInsertCompleteTag:@"groupId" withLevel:3 withString:[NSString stringWithFormat:@"%d", (int) fileStat.st_gid]];
        [self xmlInsertCompleteTag:@"modifiedTime" withLevel:3 withString:[NSString stringWithUTF8String:modifiedTime]];
        [self xmlInsertCompleteTag:@"accessTime" withLevel:3 withString:[NSString stringWithUTF8String:accessTime]];
        [self xmlInsertCompleteTag:@"birthTime" withLevel:3 withString:[NSString stringWithUTF8String:birthTime]];
        [self xmlInsertCompleteTag:@"statusChangeTime" withLevel:3 withString:[NSString stringWithUTF8String:statusChangeTime]];
#else
        // FILE TYPE | FILE SIZE | FILE MODE  | USER ID | GROUP ID | BIRTH TIME | MODIFIED TIME | ACCESS TIME | STATUS CHANGE TIME
        NSString *fileStatLine = [NSString stringWithFormat:@"%s | %llu | %04X | %d | %d | %ld | %ld | %ld | %ld", 
                                    fileType,
                                    (unsigned long long) fileStat.st_size,
                                    (unsigned int) [self modeToHex:fileStat.st_mode],
                                    (int) fileStat.st_uid,
                                    (int) fileStat.st_gid,
                                    (long) fileStat.st_birthtime,
                                    (long) fileStat.st_mtime,
                                    (long) fileStat.st_atime,
                                    (long) fileStat.st_ctime];
        
        [self xmlInsertCompleteTag:@"fileStat" withLevel:3 withString:fileStatLine];                                        
#endif
        
        [self xmlInsertEndTag:@"filePathInfo" withLevel:2];
        
        if (S_ISDIR(fileStat.st_mode))
        {
            // recurse direcotries
            [self walkDirectoryRecursive:fullPath];
        }
    }
    
    [innerPool drain];
    
    closedir(dir);
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
    // set progress bar to indeterminate
    [self updateProgress:-1.0];
    
    [self xmlInsertStartTag:@"filePathInfos" withLevel:1];
    
	[self walkDirectoryRecursive:@"/"];
    
    [self xmlInsertEndTag:@"filePathInfos" withLevel:1];
    
	[self acquisitionComplete];
	
    if ([self cancelAcquisition])
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ACQUISITION_CANCELLED];
		return [self moduleStatus];
	}
    
	return COLLECTIONMODULE_STATUS_OK;
}

@end
