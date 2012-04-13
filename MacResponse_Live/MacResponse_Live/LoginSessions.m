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

#import "LoginSessions.h"
#import "CaseLog.h"

#import <utmpx.h>
#import <time.h>


@implementation LoginSessions

- (id)init
{
	[super init];
	[self setModuleName: @"Login Sessions"];
	[self setModuleShortName:@"LoginSessions"];		
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
	
	[self xmlInsertStartTag:@"loginSessions" withLevel:1];
	
	setutxent();
	
	struct utmpx *utx;
    // getutxent populates a utmpx data structure
    //
    // utmpx as defined in utmpx.h
    // struct utmpx {
	//   char ut_user[_UTX_USERSIZE];	/* login name */
	//   char ut_id[_UTX_IDSIZE];	    /* id */
	//   char ut_line[_UTX_LINESIZE];	/* tty name */
	//   pid_t ut_pid;			        /* process id creating the entry */
	//   short ut_type;			        /* type of this entry */
	//   struct timeval ut_tv;		    /* time entry was created */
	//   char ut_host[_UTX_HOSTSIZE];	/* host name */
	//   __uint32_t ut_pad[16];		    /* reserved for future use */
    // };
	while ((utx = getutxent()) != NULL)
	{
		[self xmlInsertStartTag:@"loginSession" withLevel:2];
		
		[self xmlInsertCompleteTag:@"userName" withLevel:3 withString:[NSString stringWithFormat:@"%s", utx->ut_user]];
		[self xmlInsertCompleteTag:@"sessionId" withLevel:3 withString:[NSString stringWithFormat:@"%s", utx->ut_id]];
		[self xmlInsertCompleteTag:@"sessionName" withLevel:3 withString:[NSString stringWithFormat:@"%s", utx->ut_line]];
		[self xmlInsertCompleteTag:@"pid" withLevel:3 withString:[NSString stringWithFormat:@"%d", utx->ut_pid]];
		[self xmlInsertCompleteTag:@"sessionType" withLevel:3 withString:[NSString stringWithFormat:@"%d", utx->ut_type]];
		
		struct tm *nowtm = localtime(&utx->ut_tv.tv_sec);
		char tmbuf[64];
		strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
		
		[self xmlInsertCompleteTag:@"sessionTime" withLevel:3 withString:[NSString stringWithFormat:@"%s", tmbuf]];

		
		[self xmlInsertEndTag:@"loginSession" withLevel:2];
	}
	
	[self xmlInsertEndTag:@"loginSessions" withLevel:1];
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end
