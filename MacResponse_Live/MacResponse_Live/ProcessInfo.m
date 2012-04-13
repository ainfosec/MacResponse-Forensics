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

#import <sys/sysctl.h>

#import <libproc.h>
#import <pwd.h>
#import "ProcessInfo.h"
#import	"CaseLog.h"

#include <netinet/in.h>
#include <netdb.h>

@implementation ProcessInfo

- (id)init
{
	[super init];
	[self setModuleName: @"Process Information"];
	[self setModuleShortName:@"ProcessInformation"];	
	[self setModuleEnabled: TRUE];
	
	// For the Process Information module, root privileges is preferred
	// but not necessary.  This module will run without root privileges,
	// but may result in incomplete data
	if (geteuid() == 0)
	{
		[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	}
	else 
	{
		[self setModuleStatus: COLLECTIONMODULE_STATUS_WARNING_INSUFFICIENT_PERMISSIONS];
	}
	
	return self;
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}

	size_t bufSize = 0;
    // build the management information base (mib) to retrieve process information from sysctl
	int mibProcPid[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
	
    // get size needed to store process information
	if (sysctl(mibProcPid, 4, NULL, &bufSize, NULL, 0) < 0) 
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
    }
	
	struct kinfo_proc *procInfo = (struct kinfo_proc *)malloc(bufSize);
	
	if (sysctl(mibProcPid, 4, procInfo, &bufSize, NULL, 0) < 0)
	{
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
	}

	unsigned long numProcs = bufSize / sizeof(struct kinfo_proc);
	int i;
	
	[self xmlInsertStartTag:@"processes" withLevel:1];
	for (i = 0; i < numProcs; i++)
	{
		pid_t pid = procInfo[i].kp_proc.p_pid;
		LogDebugObjc(@"PID: %d\n", pid);

		[self xmlInsertStartTag:@"process" withLevel:2];
		
		[self xmlInsertCompleteTag:@"pid" withLevel:3 withString:[NSString stringWithFormat:@"%d", pid]];
		[self xmlInsertCompleteTag:@"ppid" withLevel:3 withString:[NSString stringWithFormat:@"%d", procInfo[i].kp_eproc.e_ppid]];
		[self xmlInsertCompleteTag:@"processName" withLevel:3 withString:[NSString stringWithFormat:@"%s", procInfo[i].kp_proc.p_comm]];
		
		// the command line arguments and environment variables are only accessible
		// if we are running as root
		if ((geteuid() == 0) && (pid > 0))
		{
			[self getCommandLineArgs:pid];
		}
		
		[self xmlInsertStartTag:@"openFiles" withLevel:3];
		
		// get Current Working Directory information for this process
		[self getCWDInfo:pid];
		
		// get Text File information for this process
		[self getTextFileInfo:pid];
		
		// get File Descriptor information for this process
		[self getFDInfo:pid];
		
		[self xmlInsertEndTag:@"openFiles" withLevel:3];
		
		[self xmlInsertEndTag:@"process" withLevel:2];
	}
	
	[self xmlInsertEndTag:@"processes" withLevel:1];
	free(procInfo);
	
	[self acquisitionComplete];

	return COLLECTIONMODULE_STATUS_OK;
}

- (void) getCommandLineArgs:(pid_t) pid
{
	LogDebugObjc(@"Getting command line arguments for this PID: %d\n", pid);
	
    // build mib for retrieving command line arguments for a given pid
	int mibProcArgs[3] = {CTL_KERN, KERN_PROCARGS, (int)pid};
	
	char *procArgs;
	size_t argLen;
	
    
    // get size
	if (sysctl(mibProcArgs, 3, NULL, &argLen, NULL, 0) == -1)
	{
		LogDebugObjc(@"Unable to get Process Arguments size (%d)\n", pid);
		return;
	}
	
    // call sysctl for command line args
	procArgs = malloc(argLen * sizeof(char));
	if (sysctl(mibProcArgs, 3, procArgs, &argLen, NULL, 0) == -1)
	{
		LogDebugObjc(@"Unable to get Process Arguments (%d)\n", pid);
		return;
	}
	
	NSString *processArg = @"";
	
	// HACK, for now to get command line args and environment variables printed out
	//   ** assumption 1 - all command line arguments come before the environment variables
	//   ** assumption 2 - there are no '=' in the command line arguments (this is where things can go bad)
	
	int isCmdLine = 1;
	[self xmlInsertStartTag:@"commandLineArgs" withLevel:3];
	
	int i;
	for (i = 0; i < argLen; i++)
	{
        // the data appears to be padded with 0xffffffff, so when we come across this value we can stop
		if (procArgs[i] == 0xffffffff)
		{
			break;
		}
		
        // if we reach '\0', we have hit the end of an item (either command line or environment variable)
        // there may be multiple '\0', so when we see one make sure we actually have data, otherwise move on
		if (procArgs[i] == '\0')
		{
			if ([processArg length] > 0)
			{
				// hack to determine if '=' is present, indication environment variable
				NSArray *argArray = [processArg componentsSeparatedByString:@"="];
                // '=' was not present, must be command line arg
				if ([argArray count] == 1)
				{
					// assume command line argument
					[self xmlInsertStartTag:@"commandLineArg" withLevel:4];
					[self xmlInsertCompleteTag:@"commandLineArgValue" withLevel:5 withString:processArg];
					[self xmlInsertEndTag:@"commandLineArg" withLevel:4];
				}
                // we had an '=', assume environment variable
				else if ([argArray count] == 2)
				{
                    // if isCmdLine = 1, then this is the first env variable and we need
                    // to close out the commandLineArgs XML tag
					if (isCmdLine)
					{
						isCmdLine = 0;
						[self xmlInsertEndTag:@"commandLineArgs" withLevel:3];
						[self xmlInsertStartTag:@"environmentVariables" withLevel:3];
					}
					
					[self xmlInsertStartTag:@"environmentVariable" withLevel:4];
					[self xmlInsertCompleteTag:@"environmentVariableValue" withLevel:5 withString:processArg];
					[self xmlInsertEndTag:@"environmentVariable" withLevel:4];
				}
			}
			
			processArg = @"";
		}
		else 
		{
			processArg = [processArg stringByAppendingFormat:@"%c", procArgs[i]];
		}
	}
	if (isCmdLine)
	{
		[self xmlInsertEndTag:@"commandLineArgs" withLevel:3];
	}
	else 
	{
		[self xmlInsertEndTag:@"environmentVariables" withLevel:3];
	}
}

- (void) getCWDInfo:(pid_t) pid
{
	LogDebugObjc(@"Getting Current Working Directory information for this PID: %d\n", pid);
	
    // proc_vnodepathinfo contains
    //      vnode_info_path     pvi_cdr     ** which contains
    //          char        vip_path[MAXPATHLEN];       ** which gives the current working directory
    //                                                  ** for this process
    //
    // more information on these structures can be found in proc_info.h
	struct proc_vnodepathinfo vnodePathInfo;
    
    // call proc_pidinfo, with PROC_PIDVNODEPATHINFO to retrieve proc_vnodepathinfo data
	NSInteger sizeVnodeInfo = proc_pidinfo((int)pid, PROC_PIDVNODEPATHINFO, 0, &vnodePathInfo, sizeof(vnodePathInfo));
	if (sizeVnodeInfo <= 0)
	{
		LogDebugObjc(@"Unable to get CWD information for this pid: %d\n", pid);
		return;
	}
	
	[self xmlInsertStartTag:@"openFile" withLevel:4];
	[self xmlInsertCompleteTag:@"fileDescriptor" withLevel:5 withString:@"cwd"];
	[self xmlInsertCompleteTag:@"fileType" withLevel:5 withString:@"DIR"];
	[self xmlInsertCompleteTag:@"filePath" withLevel:5 withString:[NSString stringWithFormat:@"%s", vnodePathInfo.pvi_cdir.vip_path]];
	
	[self xmlInsertEndTag:@"openFile" withLevel:4];
}

- (void) getTextFileInfo: (pid_t) pid
{
	LogDebugObjc(@"Getting Text File informtion for this PID: %d\n", pid);

    // information on the proc_regionwithpathinfo and the subsequent data structures
    // referenced in this function can be found in proc_info.h
	struct proc_regionwithpathinfo regionPathInfo;
	long long last_ino = 0;
	uint64_t address = (uint64_t)0;
	for (int i = 0; i < 10000; i++)
	{
        // for each region, as identified by address, get proc_regionwithpathinfo data to retrieve text file information
        // for this process
		NSInteger sizeRegionInfo = proc_pidinfo((int)pid, PROC_PIDREGIONPATHINFO, address, &regionPathInfo, sizeof(regionPathInfo));
		if (sizeRegionInfo <= 0)
		{
			// nothing else to see here
			return;
		}
		else if (sizeRegionInfo < sizeof(regionPathInfo))
		{
			LogDebugObjc(@"An error occurred getting Text File information\n");
			return;
		}
		
        
        // if file serial number (vst_ino) is same as last file, skip
		if ((regionPathInfo.prp_vip.vip_path[0]) && (regionPathInfo.prp_vip.vip_vi.vi_stat.vst_ino != last_ino))
		{
			[self xmlInsertStartTag:@"openFile" withLevel:4];
			
			[self xmlInsertCompleteTag:@"fileDescriptor" withLevel:5 withString:@"txt"];
			[self xmlInsertCompleteTag:@"fileType" withLevel:5 withString:@"REG"];
			[self xmlInsertCompleteTag:@"filePath" withLevel:5 withString:[NSString stringWithFormat:@"%s", regionPathInfo.prp_vip.vip_path]];
			
			[self xmlInsertEndTag:@"openFile" withLevel:4];
			
			last_ino = regionPathInfo.prp_vip.vip_vi.vi_stat.vst_ino;
		}
		
        // advance the address pointer
		address = regionPathInfo.prp_prinfo.pri_address + regionPathInfo.prp_prinfo.pri_size;
	}
}

- (void) getFDInfo:(pid_t) pid
{
	LogDebugObjc(@"Getting File Descriptor information for this PID: %d\n", pid);
	
	int ret;
    // get the size needed to store the file descriptor information for this process
	ret = proc_pidinfo((int)pid, PROC_PIDLISTFDS, 0, 0, 0);
	if (ret == -1)
	{
		LogDebugObjc(@"An error occurred getting File Descriptor information\n");
		return;
	}
	
	size_t buffersize = (size_t)ret;
	
    // allocate the buffer
    char *buffer = (char *)malloc((size_t)buffersize);
    if (!buffer) 
	{
        LogDebugObjc(@"An error occurred getting File Descriptor information\n");
		return;
    }
	
    // call proc_pidinfor with PROC_PIDLISTFDS to get file descriptor information
	ret = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, (int)buffersize);
	
    // proc_fdinfo found in proc_info.h
    //  struct proc_fdinfo {
	//      int32_t			proc_fd;
	//      uint32_t		proc_fdtype;	
    //  };
    struct proc_fdinfo *infop;
    
    //get the number of file descriptors
    uint64_t nfd = ret / sizeof(struct proc_fdinfo);
    
    // point to the first FD
    infop = (struct proc_fdinfo *)buffer;
	
    int i;
	
    for (i = 0; i < nfd; i++)
	{
        // The possible types are:
        //      PROX_FDTYPE_ATALK
        //      PROX_FDTYPE_VNODE
        //      PROX_FDTYPE_SOCKET
        //      PROX_FDTYPE_PSHM
        //      PROX_FDTYPE_PSEM
        //      PROX_FDTYPE_KQUEUE
        //      PROX_FDTYPE_PIPE
        //      PROX_FDTYPE_FSEVENTS
        //
        // For now we are only interested in PROX_FDTYPE_VNODE and PROX_FDTYPE_SOCKET
		if (infop[i].proc_fdtype == PROX_FDTYPE_VNODE)
		{
            // call proc_pidfdinfo with PROC_PIDFDVNODEPATHINFO to get fd information for this type
			struct vnode_fdinfowithpath vnodePathInfo;
			NSInteger sizeVnodeInfo = proc_pidfdinfo((int)pid, infop[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vnodePathInfo, sizeof(vnodePathInfo));
			if (sizeVnodeInfo <= 0)
			{
				LogDebugObjc(@"An error occurred getting VNode Info\n");
				return;
			}
			else if (sizeVnodeInfo < sizeof(vnodePathInfo))
			{
				LogDebugObjc(@"Too few bytes returned for VNode Info (expected: %d, got: %d)\n", sizeof(vnodePathInfo), sizeVnodeInfo);
				return;
			}
			
			[self xmlInsertStartTag:@"openFile" withLevel:4];
			
            // call getFileDescriptor
			[self xmlInsertCompleteTag:@"fileDescriptor" withLevel:5 withString:[self getFileDescriptor:infop[i].proc_fd withOpenFlags:vnodePathInfo.pfi.fi_openflags]];
			
            // check the mode to record the file type
			NSString *mode = @"";
			switch (vnodePathInfo.pvip.vip_vi.vi_stat.vst_mode & S_IFMT)
			{
				case S_IFREG:
					mode = @"REG";
					break;
				case S_IFIFO:
					mode = @"FIFO";
					break;
				case S_IFCHR:
					mode = @"CHR";
					break;
				case S_IFDIR:
					mode = @"DIR";
					break;
				case S_IFBLK:
					mode = @"BLK";
					break;
				default:
					mode = @"REG";
					break;
			}
			
			[self xmlInsertCompleteTag:@"fileType" withLevel:5 withString:mode];
			[self xmlInsertCompleteTag:@"filePath" withLevel:5 withString:[NSString stringWithFormat:@"%s", vnodePathInfo.pvip.vip_path]];
			
			[self xmlInsertEndTag:@"openFile" withLevel:4];
		}
		else if (infop[i].proc_fdtype == PROX_FDTYPE_SOCKET)
		{
			struct socket_fdinfo socketInfo;
			
            // call proc_pidfdinfo with PROC_PIDFDSOCKETINFO to populate socket_fdinfo data structure with SOCKET type file descriptor information
			int sizeSocketInfo = proc_pidfdinfo((int)pid, infop[i].proc_fd, PROC_PIDFDSOCKETINFO, &socketInfo, sizeof(socketInfo));
			if (sizeSocketInfo <= 0)
			{
				LogDebugObjc(@"An error occurred getting SOCKET Info\n");
				return;
			}
			else if (sizeSocketInfo < sizeof(socketInfo))
			{
				LogDebugObjc(@"Too few bytes returned for SOCKET Info (expected: %d, got: %d)\n", sizeof(socketInfo), sizeSocketInfo);
				return;
			}
			
			int fam;
			NSString *type = nil;
			NSString *localNetworkAddr = nil;
			NSString *localNetworkPort = nil;
			NSString *foreignNetworkAddr = nil;
			NSString *foreignNetworkPort = nil;
			NSString *protocol = nil;
			
			switch (fam = socketInfo.psi.soi_family)
			{
                // for family type internet (IPv4 or IPv6)
                case AF_INET:
				case AF_INET6:
					type = (fam == AF_INET) ? @"IPv4" : @"IPv6";
					
                    // build the IPv4 local and foreign addresses (and ports) for this process
					if (fam == AF_INET)
					{
						struct in_addr *localAddr, *foreignAddr;
						int localPort, foreignPort;
						if (socketInfo.psi.soi_kind == SOCKINFO_TCP)
						{
							protocol = @"TCP";
							localAddr = (struct in_addr *)&socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4;
							localPort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
							foreignAddr = (struct in_addr *)&socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4;
							foreignPort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport;
						}
						else 
						{
							protocol = @"UDP";
							localAddr = (struct in_addr *)&socketInfo.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4;
							localPort = (int)socketInfo.psi.soi_proto.pri_in.insi_lport;
							foreignAddr = (struct in_addr *)&socketInfo.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4;
							foreignPort = (int)socketInfo.psi.soi_proto.pri_in.insi_fport;
						}
						
						if (localAddr->s_addr == INADDR_ANY)
						{
							localNetworkAddr = @"*";
						}
						else 
						{
							localNetworkAddr = [NSString stringWithFormat:@"%u.%u.%u.%u", (localAddr->s_addr) & 0xff,
										 (localAddr->s_addr >> 8) & 0xff,
										 (localAddr->s_addr >> 16) & 0xff,
										 (localAddr->s_addr >> 24) & 0xff];
						}
						if (localPort == 0)
						{
							localNetworkPort = @"*";
						}
						else 
						{
							localNetworkPort = [NSString stringWithFormat:@"%d", ntohs((u_short)localPort)];
						}
						
						if (foreignAddr->s_addr == INADDR_ANY)
						{
							foreignNetworkAddr = @"*";
						}
						else 
						{
							foreignNetworkAddr = [NSString stringWithFormat:@"->%u.%u.%u.%u", (foreignAddr->s_addr) & 0xff,
										   (foreignAddr->s_addr >> 8) & 0xff,
										   (foreignAddr->s_addr >> 16) & 0xff,
										   (foreignAddr->s_addr >> 24) & 0xff];
						}	
						if (foreignPort == 0)
						{
							foreignNetworkPort = @"*";
						}
						else 
						{
							foreignNetworkPort = [NSString stringWithFormat:@"%d", ntohs((u_short)foreignPort)];
						}
					}
                    // build the IPv6 local and foreign addresses (and ports) for this process
					else 
					{
						struct in6_addr *localAddr, *foreignAddr;
						int localPort, foreignPort;
						if (socketInfo.psi.soi_kind == SOCKINFO_TCP)
						{
							protocol = @"TCP";
							localAddr = (struct in6_addr *)&socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6;
							localPort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport;
							foreignAddr = (struct in6_addr *)&socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6;
							foreignPort = (int)socketInfo.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport;
						}
						else 
						{
							protocol = @"UDP";
							localAddr = (struct in6_addr *)&socketInfo.psi.soi_proto.pri_in.insi_laddr.ina_6;
							localPort = (int)socketInfo.psi.soi_proto.pri_in.insi_lport;
							foreignAddr = (struct in6_addr *)&socketInfo.psi.soi_proto.pri_in.insi_faddr.ina_6;
							foreignPort = (int)socketInfo.psi.soi_proto.pri_in.insi_fport;
						}
						
						if (IN6_IS_ADDR_UNSPECIFIED(localAddr))
						{
							localNetworkAddr = @"*";
						}
						else 
						{
							struct sockaddr_in6	lsin6;
							memset(&lsin6, 0, sizeof(lsin6));
							lsin6.sin6_len = sizeof(lsin6);
							lsin6.sin6_family = AF_INET6;
							lsin6.sin6_addr = *localAddr;
							
							char lbuffer[NI_MAXHOST];
							getnameinfo((struct sockaddr *)&lsin6, lsin6.sin6_len, lbuffer, sizeof(lbuffer), NULL, 0, NI_NUMERICHOST);
							
							localNetworkAddr = [NSString stringWithFormat:@"%s", lbuffer];
						}
						if (localPort == 0)
						{
							localNetworkPort = @"*";
						}
						else 
						{
							localNetworkPort = [NSString stringWithFormat:@"%d", ntohs((u_short)localPort)];
						}
						if (IN6_IS_ADDR_UNSPECIFIED(foreignAddr))
						{
							foreignNetworkAddr = @"*";
						}
						else 
						{
							struct sockaddr_in6	fsin6;
							memset(&fsin6, 0, sizeof(fsin6));
							fsin6.sin6_len = sizeof(fsin6);
							fsin6.sin6_family = AF_INET6;
							fsin6.sin6_addr = *foreignAddr;
							
							char fbuffer[NI_MAXHOST];
							getnameinfo((struct sockaddr *)&fsin6, fsin6.sin6_len, fbuffer, sizeof(fbuffer), NULL, 0, NI_NUMERICHOST);
							
							foreignNetworkAddr = [NSString stringWithFormat:@"%s", fbuffer];
						}
						if (foreignPort == 0)
						{
							foreignNetworkPort = @"*";
						}
						else 
						{
							foreignNetworkPort = [NSString stringWithFormat:@"%d", ntohs((u_short)foreignPort)];
						}
					}
					break;
                // Other families we may want to consider in the future include:
                //      AF_UNIX
                //      AF_ROUTE
                //      AF_NDRV
                //      AF_SYSTEM
                //      AF_PPP
			}
			
			if (type)
			{
				[self xmlInsertStartTag:@"openFile" withLevel:4];
				[self xmlInsertCompleteTag:@"fileDescriptor" withLevel:5 withString:[self getFileDescriptor:infop[i].proc_fd withOpenFlags:socketInfo.pfi.fi_openflags]];
				[self xmlInsertCompleteTag:@"fileType" withLevel:5 withString:type];
				
				if ((localNetworkAddr) && (foreignNetworkAddr))
				{
					[self xmlInsertStartTag:@"localNetworkAddress" withLevel:5];
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:6 withString:localNetworkAddr];
					[self xmlInsertCompleteTag:@"networkPortValue" withLevel:6 withString:localNetworkPort];
					[self xmlInsertEndTag:@"localNetworkAddress" withLevel:5];
					
					[self xmlInsertStartTag:@"foreignNetworkAddress" withLevel:5];
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:6 withString:foreignNetworkAddr];
					[self xmlInsertCompleteTag:@"networkPortValue" withLevel:6 withString:foreignNetworkPort];
					[self xmlInsertEndTag:@"foreignNetworkAddress" withLevel:5];
				}
				
				if (protocol)
				{
					[self xmlInsertCompleteTag:@"fileProtocol" withLevel:5 withString:protocol];
				}
				
				[self xmlInsertEndTag:@"openFile" withLevel:4];
			}
		}
		else
		{
			LogDebugObjc(@"Other FD Type (%d), yet to be parsed\n", infop[i].proc_fdtype);
		}
	}
}

- (NSString *) getFileDescriptor:(NSInteger)fd withOpenFlags:(NSInteger)openFlags
{
    // build file descriptor string
	NSInteger flag = openFlags & (FREAD | FWRITE);
	NSString *permFlag = @"";
	if (flag == FREAD)
	{
		permFlag = @"r";
	}
	else if (flag == FWRITE)
	{
		permFlag = @"w";
	}
	else if (flag == (FREAD | FWRITE))
	{
		permFlag = @"u";
	}
	
	return [NSString stringWithFormat:@"%d%@", fd, permFlag];
}

@end
