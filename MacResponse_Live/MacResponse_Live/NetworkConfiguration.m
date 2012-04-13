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

#import "NetworkConfiguration.h"
#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#import "CaseLog.h"

#include <stdio.h>

char *flags[16] = {"UP", "BROADCAST", "DEBUG", "LOOPBACK", "P2P", "SMART", "RUNNING", "NOARP", "PROMISC", "ALLMULTI", "OACTIVE", "SIMPLEX", "LINK0", "LINK1", "LINK2", "MULTICAST"};

@implementation NetworkConfiguration

- (id)init
{
	[super init];
	[self setModuleName: @"Network Configuration"];
	[self setModuleShortName:@"NetworkConfiguration"];	
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
	
	// Build the Management Information Base (MIB) for polling Sysctl for
	//  Network Configuration information
	int mibNetworkInfo[6] = {CTL_NET,
		PF_ROUTE,
		0,
		0,
		NET_RT_IFLIST,
		0};
	
	// Get the size of the buffer required to store the Network 
	//  Configuration data
	size_t size;
	sysctl(mibNetworkInfo, 6, NULL, &size, NULL, 0);
	
	char *buf = malloc(size);
	
	// Retrieve data
	sysctl(mibNetworkInfo, 6, buf, &size, NULL, 0);
	
    // pointer to the end of the network configuration data
	char *limit = buf + size;
    
    // pointer to the current location in the netowrk configuration data
	char *next = buf;
    
    // interface message header
	struct if_msghdr *interfaceMsg;
    
    // interface address message header
	struct ifa_msghdr *interfaceAddressMsg;
    
	int currentIndex = 0;
	int i;
	int firstAddr = 1;
	
	[self xmlInsertStartTag:@"networkInterfaces" withLevel:1];
	
	while (next < limit)
	{
		// Get the next interface message header
		//
		// struct if_msghdr {
        //  unsigned short  ifm_msglen;     /* to skip over non-understood messages */
        //  unsigned char   ifm_version;    /* future binary compatability */
        //  unsigned char   ifm_type;       /* message type */
        //  int             ifm_addrs;      /* like rtm_addrs */
        //  int             ifm_flags;      /* value of if_flags */
		//  unsigned short  ifm_index;      /* index for associated ifp */
        //  struct  if_data ifm_data;       /* statistics and other data about if */
		// };
		interfaceMsg = (struct if_msghdr *)next;

		// RTM_IFINFO indicates a new interface
		if (interfaceMsg->ifm_type == RTM_IFINFO)
		{
			LogDebugObjc(@"New interface detected\n");
			
			// If this is not the first interface, firstAddr will be 0,
			//  indicating that we need to close the 'addresses' xml tag 
			//  for the previous interface
			if (firstAddr == 0)
			{
				firstAddr = 1;
				[self xmlInsertEndTag:@"networkAddresses" withLevel:3];
			}

			// if we are starting a new interface, insert closing tag for previous interface
			if (currentIndex != 0)
			{
				[self xmlInsertEndTag:@"networkInterface" withLevel:2];
			}
			currentIndex = interfaceMsg->ifm_index;
			
			[self xmlInsertStartTag:@"networkInterface" withLevel:2];
			
			// Get Link-Level Socket Address structure for this interface
			// 
			// struct sockaddr_dl {
			// 	u_char  sdl_len;        /* Total length of sockaddr */
			//	u_char  sdl_family;     /* AF_LINK */
			//	u_short sdl_index;      /* if != 0, system given index for interface */
			//	u_char  sdl_type;       /* interface type */
			//	u_char  sdl_nlen;       /* interface name length, no trailing 0 reqd. */
			//	u_char  sdl_alen;       /* link level address length */
			//	u_char  sdl_slen;       /* link layer selector length */
			//	char    sdl_data[12];   /* minimum work area, can be larger;                                                                                            
			// };
			struct sockaddr_dl *socketAddr_dl = (struct sockaddr_dl *)(interfaceMsg + 1);
			char name[12];
			strncpy(name, socketAddr_dl->sdl_data, socketAddr_dl->sdl_nlen);
			name[socketAddr_dl->sdl_nlen] = '\0';
			LogDebugObjc(@"Name: %s\n", name);
			
			[self xmlInsertCompleteTag:@"networkInterfaceName" withLevel:3 withString:[NSString stringWithFormat:@"%s", name]];
			
			// Report interface flags if there are any
			if (interfaceMsg->ifm_flags)
			{
				[self xmlInsertStartTag:@"networkInterfaceFlags" withLevel:3];
				int i;
				for (i = 0; i < 16; i++)
				{
					if (interfaceMsg->ifm_flags & (1 << i))
					{
						[self xmlInsertStartTag:@"networkInterfaceFlag" withLevel:4];
						[self xmlInsertCompleteTag:@"networkInterfaceFlagValue" withLevel:5 withString:[NSString stringWithFormat:@"%s", flags[i]]];
						[self xmlInsertEndTag:@"networkInterfaceFlag" withLevel:4];						
					}
				}
				[self xmlInsertEndTag:@"networkInterfaceFlags" withLevel:3];
			}
			
			// If this iterface has a link-level address
			if (socketAddr_dl->sdl_alen)
			{
				// get lladdr here, starting at sdl->sdl_data + sdl->sdl_nlen
				NSString *lladdr;
				if (socketAddr_dl->sdl_type == IFT_ETHER)
				{
					lladdr = @"ether";
				}
				else 
				{
					lladdr = @"lladdr";
				}

				for (i = 0; i < socketAddr_dl->sdl_alen; i++)
				{
					lladdr = [lladdr stringByAppendingFormat:@":%02x", socketAddr_dl->sdl_data[socketAddr_dl->sdl_nlen+i] & 0xff];
				}
				
				[self xmlInsertCompleteTag:@"networkLocalLinkAddress" withLevel:3 withString:[NSString stringWithFormat:@"%@", lladdr]];
			}
		}
		// RTM_NEWADDR indicates a new address for the current interface
		else if (interfaceMsg->ifm_type == RTM_NEWADDR)
		{
			// if this is the first address for this interface, open the 
			//  'addresses' xml start tag
			if (firstAddr)
			{
				firstAddr = 0;
				[self xmlInsertStartTag:@"networkAddresses" withLevel:3];
			}
			
			LogDebugObjc(@"New address detected\n");
			if (interfaceMsg->ifm_index != currentIndex)
			{
				LogDebugObjc(@"Out of sync parsing occurred\n");
				// should cleanly break out of processing here
			}
			
			// Get the Interface Address Message Header
			//struct ifa_msghdr {
			//	unsigned short  ifam_msglen;    /* to skip over non-understood messages */
			//	unsigned char   ifam_version;   /* future binary compatability */
			//	unsigned char   ifam_type;      /* message type */
			//	int             ifam_addrs;     /* like rtm_addrs */
			//	int             ifam_flags;     /* value of ifa_flags */
			//	unsigned short  ifam_index;     /* index for associated ifp */
			//	int             ifam_metric;    /* value of ifa_metric */
			//};
			interfaceAddressMsg = (struct ifa_msghdr *)interfaceMsg;
			LogDebugObjc(@"Addr: 0x%02x\n", interfaceAddressMsg->ifam_addrs);
			
			uint32_t offset = 0;
			struct sockaddr *saNetmask = nil;
			struct sockaddr *saIFA = nil;
			struct sockaddr *saBRD = nil;
			struct sockaddr *sa;
			caddr_t cp = (char  *)(interfaceAddressMsg + 1);
			
			// There are 8 possible socket addresses, multiple of which
			//  can be present at the same time 
			// 
			// 0 - RTAX_DST - destination sockaddr
			// 1 - GATEWAY - gateway sockaddr
			// 2 - NETMASK - netmask sockaddr
			// 3 - GENMASK - cloning mask sockaddr
			// 4 - IFP - interface name sockaddr
			// 5 - IFA - interface address sockaddr
			// 6 - AUTHOR - sockaddr for author of redirect
			// 7 - BRD - broadcast sockaddr
			for (i = 0; i < 8; i++)
			{
				if (interfaceAddressMsg->ifam_addrs & (1 << i))
				{
					cp += offset;
					sa = (struct sockaddr *)cp;
					
					if (sa->sa_len > 0)
					{
						offset = 1 + (((uint32_t)sa->sa_len - 1) | ((uint32_t)sizeof(uint32_t) - 1));
					}
					else 
					{
						offset = sizeof(uint32_t);
					}
					LogDebugObjc(@"Offset: %d\n", offset);
					
					// For now, we are only interested in three socket addresses:
					//  NETMASK, IFA, and BRD
					switch (i)
					{
						case (2):
							LogDebugObjc(@"Getting Netmask\n");
							saNetmask = sa;
							break;
						case (5):
							LogDebugObjc(@"Getting IFA\n");
							saIFA = sa;
							break;
						case (7):
							LogDebugObjc(@"Getting BRD\n");
							saBRD = sa;
							break;
						default:
							LogDebugObjc(@"Not interested in this address (%d)\n", i);
							break;
					}
				}
			}
			
			// start by looking at RTAX_IFA (interface address)
			if (saIFA)
			{
				[self xmlInsertStartTag:@"networkAddress" withLevel:4];
				
				if (saIFA->sa_family == AF_INET)
				{
					LogDebugObjc(@"INET\n");
					[self xmlInsertCompleteTag:@"networkAddressType" withLevel:5 withString:@"INET"];
					
					struct sockaddr_in *sin = (struct sockaddr_in *)saIFA;
					
                    //build IPv4 address
					int iVal = sin->sin_addr.s_addr;
					NSString *inetValue = [NSString stringWithFormat:@"%d", (int)(iVal & 0xff)];
					int i;
					for (i = 0; i < 3; i++)
					{
						iVal = iVal >> 8;
						inetValue = [inetValue stringByAppendingFormat:@".%d", (int)(iVal & 0xff)];
					}
					LogDebugObjc(@"%@\n", inetValue);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:5 withString:inetValue];
					
					// Netmask and Broadcast are only relevant for AF_INET
					if (saNetmask && saNetmask->sa_len > 0)
					{
						LogDebugObjc(@"Netmask...\n");
						sin = (struct sockaddr_in *)saNetmask;
						if (sin)
						{
							int nVal = sin->sin_addr.s_addr;
							NSString *netmask = [NSString stringWithFormat:@"0x%02x", nVal & 0xff];
							for (i = 0; i < 3; i++)
							{
								nVal = nVal >> 8;
								netmask = [netmask stringByAppendingFormat:@"%02x", nVal & 0xff];
							}
							LogDebugObjc(@"%@\n", netmask);
							[self xmlInsertCompleteTag:@"networkNetmask" withLevel:5 withString:netmask];
						}
					}
					
					if (saBRD && saBRD->sa_len > 0)
					{
						LogDebugObjc(@"Broadcast...\n");
						sin = (struct sockaddr_in *)saBRD;
						if (sin && sin->sin_addr.s_addr != 0)
						{
							int bVal = sin->sin_addr.s_addr;
							NSString *broadcast = [NSString stringWithFormat:@"%d", bVal & 0xff];
							for (i = 0; i < 3; i++)
							{
								bVal = bVal >> 8;
								broadcast = [broadcast stringByAppendingFormat:@".%d", bVal & 0xff];
							}
							LogDebugObjc(@"%@\n", broadcast);
							[self xmlInsertCompleteTag:@"networkBroadcastAddress" withLevel:5 withString:broadcast];
						}
					}
				}
				else if (saIFA->sa_family == AF_INET6)
				{
					LogDebugObjc(@"INET6\n");
					[self xmlInsertCompleteTag:@"networkAddressType" withLevel:5 withString:@"INET6"];
					
                    // build IPv6 address
					struct sockaddr_in6 *sin = (struct sockaddr_in6 *)saIFA;
					char addressBuffer[513];
					int error = getnameinfo((struct sockaddr *)sin, sin->sin6_len, addressBuffer, sizeof(addressBuffer), NULL, 0, NI_NUMERICHOST|NI_WITHSCOPEID);
					
					if (error != 0)
					{
						inet_ntop(AF_INET6, &sin->sin6_addr, addressBuffer, sizeof(addressBuffer));
					}
					
					LogDebugObjc(@"%s\n", addressBuffer);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:5 withString:[NSString stringWithFormat:@"%s", addressBuffer]];
				}
				else 
				{
					LogDebugObjc(@"Other interface address type (%d)\n", saIFA->sa_family);
				}
				
				[self xmlInsertEndTag:@"networkAddress" withLevel:4];

			}
			else 
			{
				LogDebugObjc(@"No Interface Address present\n");
			}

		}
		
		next += interfaceMsg->ifm_msglen;
	}
	
	if (firstAddr == 0)
	{
		[self xmlInsertEndTag:@"networkAddresses" withLevel:3];
	}
	
	[self xmlInsertEndTag:@"networkInterface" withLevel:2];
	[self xmlInsertEndTag:@"networkInterfaces" withLevel:1];
	
	free(buf);
	
	[self acquisitionComplete];
	
	return COLLECTIONMODULE_STATUS_OK;
}

@end