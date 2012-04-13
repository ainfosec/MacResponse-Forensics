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

#include <sys/mount.h>

#import "DiskInformation.h"
#import "CaseLog.h"

@implementation DiskInformation

- (id)init
{
	[super init];
	[self setModuleName: @"Disk Information"];
	[self setModuleShortName:@"DiskInformation"];		
	[self setModuleEnabled: TRUE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	return self;
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"mountedDisks" withLevel:1];
	
	Boolean retVal = FALSE;
	switch ([Utility getOSXVersion])
	{
		case OSX_Version_10_5:
			retVal = [self getDiskInformation10_5];
			break;
		case OSX_Version_10_6:
			retVal = [self getDiskInformation10_6];
			break;
		case OSX_Version_10_7:
			// the code to get Disk Information built for OSX 10.6 works for 10.7
            retVal = [self getDiskInformation10_6];
			break;
		case OSX_Version_Unsupported:
			LogDebugObjc(@"Running on unsupported version of OS X\n");
			[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR_UNSUPPORTED_OS_VERSION];
			retVal = FALSE;
			break;
		default:
			// shouldn't get this
			[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
			retVal = FALSE;
			break;
	}
	
	[self xmlInsertEndTag:@"mountedDisks" withLevel:1];
	
	if (!retVal)
	{
		[self xmlClose];
		return [self moduleStatus];
	}
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

-(Boolean)getDiskInformation10_5
{
	struct statfs *mntbuf;
    
    // getmntinfo populates a statfs data stucture with disk information
    //
    // the information we are currently interested in from a statfs data structure is:
    //
    //   char	f_fstypename[MFSNAMELEN]; /* fs type name */
	//   char	f_mntonname[MNAMELEN];	  /* directory on which mounted */
	//   char	f_mntfromname[MNAMELEN];  /* mounted filesystem */
    //
    // details on statfs and other information we may want to consider grabbing
    // in the future can be found in mount.h
	int mntsize = getmntinfo(&mntbuf, MNT_NOWAIT);
	
	if (mntsize == 0)
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
	}
	
	int i;
	for (i = 0; i < mntsize; i++)
	{
		[self xmlInsertStartTag:@"mountedDisk" withLevel:2];
		
		LogDebugObjc(@"Disk: %s\n", &mntbuf[i].f_mntfromname);
		[self xmlInsertCompleteTag:@"diskName" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_mntfromname]];
		
		LogDebugObjc(@"Mount Point: %s\n", &mntbuf[i].f_mntonname);
		[self xmlInsertCompleteTag:@"mountPoint" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_mntonname]];
		
		LogDebugObjc(@"FS Type: %s\n", &mntbuf[i].f_fstypename);
		[self xmlInsertCompleteTag:@"fileSystemType" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_fstypename]];
		
		[self xmlInsertEndTag:@"mountedDisk" withLevel:2];
	}
	
	return TRUE;
}

-(Boolean)getDiskInformation10_6
{
	struct statfs64 *mntbuf;
    // getmntinfo64 populates a statfs64 data stucture with disk information
    //
    // the information we are currently interested in from a statfs64 data structure is:
    //
    //   char		f_fstypename[MFSTYPENAMELEN];	/* fs type name */ \
	//   char		f_mntonname[MAXPATHLEN];	/* directory on which mounted */ \
	//   char		f_mntfromname[MAXPATHLEN];	/* mounted filesystem */ \
    //
    // details on statfs64 and other information we may want to consider grabbing
    // in the future can be found in mount.h
	int mntsize = getmntinfo64(&mntbuf, MNT_NOWAIT);
	
	if (mntsize == 0)
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
	}
	
	int i;
	for (i = 0; i < mntsize; i++)
	{
		[self xmlInsertStartTag:@"mountedDisk" withLevel:2];
		
		LogDebugObjc(@"Disk: %s\n", &mntbuf[i].f_mntfromname);
		[self xmlInsertCompleteTag:@"diskName" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_mntfromname]];
		
		LogDebugObjc(@"Mount Point: %s\n", &mntbuf[i].f_mntonname);
		[self xmlInsertCompleteTag:@"mountPoint" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_mntonname]];
		
		LogDebugObjc(@"FS Type: %s\n", &mntbuf[i].f_fstypename);
		[self xmlInsertCompleteTag:@"fileSystemType" withLevel:3 withString:[NSString stringWithFormat:@"%s", &mntbuf[i].f_fstypename]];
		
		[self xmlInsertEndTag:@"mountedDisk" withLevel:2];
	}
	
	return TRUE;
}
@end