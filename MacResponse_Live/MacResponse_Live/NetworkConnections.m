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

#import "NetworkConnections.h"
#import "CaseLog.h"

#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netdb.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <arpa/inet.h>

struct protocolInfo {
	char *protocol_name;
	int protocol_ip;
	char *protocol_mib;
}; 

// protocols fpr OSX 10.6 and 10.7
struct protocolInfo proto64[] = {
	{ "tcp", IPPROTO_TCP, "net.inet.tcp.pcblist64" },
	{ "udp", IPPROTO_UDP, "net.inet.udp.pcblist64" },
    { NULL, -1 }};
// other protocols we may want to consider, but didn't seem to come up 
// in our testing include:
//      divert          net.inet.divert.pcblist64
//      ip/icmp/igmp    net.inet.raw.pcblist64

// protocols for 10.5
struct protocolInfo proto[] = {
	{ "tcp", IPPROTO_TCP, "net.inet.tcp.pcblist" },
	{ "udp", IPPROTO_UDP, "net.inet.udp.pcblist" },
    { NULL, -1 }};
// other protocols we may want to consider, but didn't seem to come up 
// in our testing include:
//      divert          net.inet.divert.pcblist
//      ip/icmp/igmp    net.inet.raw.pcblist

@implementation NetworkConnections

- (id)init
{
	[super init];
	[self setModuleName: @"Network Connections"];
	[self setModuleShortName:@"NetworkConnections"];	
	[self setModuleEnabled: TRUE];
	[self setModuleStatus: COLLECTIONMODULE_STATUS_OK];
	return self;
}

- (NSString *)moduleStatusString
{
	switch ([self moduleStatus])
	{
		case NETWORKCONNECTIONS_STATUS_ERROR_UNABLE_TO_ALLOCATE_MEMORY:
			return @"ERROR: UNABLE TO ALLOCATE MEMORY!";
		default:
			return [super moduleStatusString];
	}	
}

- (collectionmodule_status_t)acquisitionStart:(NSString *)outputPath withCompression:(Boolean)compressionEnabled
{
	if ([super acquisitionStart:outputPath withCompression:compressionEnabled] != COLLECTIONMODULE_STATUS_OK)
	{
		return [self moduleStatus];
	}
	
	[self xmlInsertStartTag:@"activeConnections" withLevel:1];
	
	Boolean retVal = FALSE;
	switch ([Utility getOSXVersion])
	{
		case OSX_Version_10_5:
			retVal = [self getNetworkConnections10_5];
			break;
		case OSX_Version_10_6:
			retVal = [self getNetworkConnections10_6];
			break;
		case OSX_Version_10_7:
			// the code to get Network Connections in OSX 10.6 works in 10.7
            retVal  = [self getNetworkConnections10_6];
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
	
	[self xmlInsertEndTag:@"activeConnections" withLevel:1];		
	
	if (!retVal)
	{
		[self xmlClose];
		return [self moduleStatus];
	}
	
    // also go out and see if we can get routing table information
	retVal = [self getRoutingTable];
	if (!retVal)
	{
		[self xmlClose];
		[self setModuleStatus:COLLECTIONMODULE_STATUS_ERROR];
		return [self moduleStatus];
	}
	
	[self acquisitionComplete];
	
	return [self moduleStatus];
}

- (Boolean)getNetworkConnections10_5
{
	LogDebugObjc(@"Running OS Verions 10.5\n");
	
	struct protocolInfo *protocol = NULL;
	for (protocol = proto; protocol->protocol_name; protocol++)
	{
		LogDebugObjc(@"Looking up network connections for protocol: %s\n", protocol->protocol_name);
		
		size_t len = 0;
        // get size needed to store data for specific sysctl item
		if (sysctlbyname(protocol->protocol_mib, 0, &len, 0, 0) < 0)
		{
			LogDebugObjc(@"Warning: Unable to get sysctl length for name: %s\n", protocol->protocol_mib);
			continue;
		}
		
		char *buf;
        // allocate appropriate amount of memory
		if ((buf = malloc(len)) == 0)
		{
			LogDebugObjc(@"Error: Unable to allocate memory\n");
			[self setModuleStatus:NETWORKCONNECTIONS_STATUS_ERROR_UNABLE_TO_ALLOCATE_MEMORY];
			return FALSE;
		}
		
        // get sysctl information
		if (sysctlbyname(protocol->protocol_mib, buf, &len, 0, 0) < 0)
		{
			LogDebugObjc(@"Warning: Unable to get sysctl data for name: %s\n", protocol->protocol_mib);
			free(buf);
			continue;
		}
		
        // make sure data returned is large enough to be valid information
		if (len <= sizeof(struct xinpgen)) {
			LogDebugObjc(@"Protocol length too small\n");
            free(buf);
            continue;
        }
		
        // the xinpgen data structure is the top level data structure that holds network 
        // connection information as returned from sysctl
        // struct	xinpgen {
        //  u_int32_t xig_len;	/* length of this structure */
        //  u_int	xig_count;	/* number of PCBs at this time */
        //  inp_gen_t xig_gen;	/* generation count at this time */
        //  so_gen_t xig_sogen;	/* socket generation count at this time */
        // };
		struct xinpgen *xig = (struct xinpgen *)buf;
        
        // inpcb holds interface PCB information and is defined in in_pcb.h
		struct inpcb *inp;
        
        // xsocket holds socket information and is defined in socketvar.h
		struct xsocket *socket;
		
        
        // for each xinpgen data element returned by sysctl
		for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
			 xig->xig_len > sizeof(struct xinpgen);
			 xig = (struct xinpgen *)((char *)xig + xig->xig_len))
		{
            // if this is TCP
			if (protocol->protocol_ip == IPPROTO_TCP)
			{
				inp = &((struct xtcpcb *)xig)->xt_inp;
				socket = &((struct xtcpcb *)xig)->xt_socket;
			}
			else 
			{
				inp = &((struct xinpcb *)xig)->xi_inp;
				socket = &((struct xinpcb *)xig)->xi_socket;
			}
			
			if (socket->xso_protocol != (int)protocol->protocol_ip)
			{
				continue;
			}
			
			if (inp->inp_vflag == 0)
				continue;
			
            // build the connection name with version number (tcp4, tcp6, udp4, etc)
			NSString *name = [NSString stringWithFormat:@"%s", protocol->protocol_name];
			LogDebugObjc(@"VFlag: 0x%08x\n", inp->inp_vflag);
			if (inp->inp_vflag & INP_IPV4)
			{
				name = [name stringByAppendingFormat:@"4"];
			}
			if (inp->inp_vflag & INP_IPV6)
			{
				name = [name stringByAppendingFormat:@"6"];
			}
			
			[self xmlInsertStartTag:@"activeConnection" withLevel:2];
			
			LogDebugObjc(@"Name: %@\n", name);
			[self xmlInsertCompleteTag:@"connectionName" withLevel:3 withString:name];
			
            // we are going to build local and foreign addresses and ports
			NSString *localAddress = @"*";
			NSString *foreignAddress = @"*";
			NSString *localPort = @"*";
			NSString *foreignPort = @"*";
			
            // if this is IPv4
			if (inp->inp_vflag & INP_IPV4)
			{
                // if the address is INADDR_ANY we leave the address as '*'
				if (!(inp->inp_laddr.s_addr == INADDR_ANY))
				{
					localAddress = [NSString stringWithFormat:@"%u.%u.%u.%u", (inp->inp_laddr.s_addr) & 0xff,
									(inp->inp_laddr.s_addr >> 8) & 0xff,
									(inp->inp_laddr.s_addr >> 16) & 0xff,
									(inp->inp_laddr.s_addr >> 24) & 0xff];
				}
                // if the port is not specified then we leave it as '*'
				if (inp->inp_lport != 0)
				{
					localPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_lport)];
				}
				
				LogDebugObjc(@"LocalAddress: %@.%@\n", localAddress, localPort);
				[self xmlInsertStartTag:@"localNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:localAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:localPort];
				[self xmlInsertEndTag:@"localNetworkAddress" withLevel:3];
				
                // build the foreign address the same as the local address
                if (!(inp->inp_faddr.s_addr == INADDR_ANY))
				{
					foreignAddress = [NSString stringWithFormat:@"%u.%u.%u.%u", (inp->inp_faddr.s_addr) & 0xff,
									  (inp->inp_faddr.s_addr >> 8) & 0xff,
									  (inp->inp_faddr.s_addr >> 16) & 0xff,
									  (inp->inp_faddr.s_addr >> 24) & 0xff];
				}
				if (inp->inp_fport != 0)
				{
					foreignPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_fport)];
				}
				
				LogDebugObjc(@"ForeignAddress: %@.%@\n", foreignAddress, foreignPort);
				[self xmlInsertStartTag:@"foreignNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:foreignAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:foreignPort];
				[self xmlInsertEndTag:@"foreignNetworkAddress" withLevel:3];
			}
            // if this is IPv6
			else if (inp->inp_vflag & INP_IPV6)
			{
                // if local address is specified use getnameinfo to build the address
				if (!(IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)))
				{
					struct sockaddr_in6	lsin6;
					memset(&lsin6, 0, sizeof(lsin6));
					lsin6.sin6_len = sizeof(lsin6);
					lsin6.sin6_family = AF_INET6;
					lsin6.sin6_addr = inp->in6p_laddr;
					
					char lbuffer[NI_MAXHOST];
					getnameinfo((struct sockaddr *)&lsin6, lsin6.sin6_len, lbuffer, sizeof(lbuffer), NULL, 0, NI_NUMERICHOST);
					
					localAddress = [NSString stringWithFormat:@"%s", lbuffer];
				}
				if (inp->inp_lport != 0)
				{
					localPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_lport)];
				}
				
				LogDebugObjc(@"LocalAddress: %@.%@\n", localAddress, localPort);
				[self xmlInsertStartTag:@"localNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:localAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:localPort];
				[self xmlInsertEndTag:@"localNetworkAddress" withLevel:3];
				
                // foreign address
				if (!(IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)))
				{
					struct sockaddr_in6	fsin6;
					memset(&fsin6, 0, sizeof(fsin6));
					fsin6.sin6_len = sizeof(fsin6);
					fsin6.sin6_family = AF_INET6;
					fsin6.sin6_addr = inp->in6p_faddr;
					
					char fbuffer[NI_MAXHOST];
					getnameinfo((struct sockaddr *)&fsin6, fsin6.sin6_len, fbuffer, sizeof(fbuffer), NULL, 0, NI_NUMERICHOST);
					
					foreignAddress = [NSString stringWithFormat:@"%s", fbuffer];
				}
				if (inp->inp_fport != 0)
				{
					foreignPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_fport)];
				}
				
				LogDebugObjc(@"Foreign: %@\n", foreignAddress);
				[self xmlInsertStartTag:@"foreignNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:foreignAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:foreignPort];
				[self xmlInsertEndTag:@"foreignNetworkAddress" withLevel:3];
			}
			
			[self xmlInsertEndTag:@"activeConnection" withLevel:2];
		}
		
		free(buf);
	}
	
	return TRUE;
}

- (Boolean)getNetworkConnections10_6
{
	LogDebugObjc(@"Running OS Version 10.6\n");
	
	struct protocolInfo *protocol = NULL;
	for (protocol = proto64; protocol->protocol_name; protocol++)
	{
		LogDebugObjc(@"Looking up network connections for protocol: %s\n", protocol->protocol_name);
		
		size_t len = 0;
        // get size of data to be returned by sysctl call
		if (sysctlbyname(protocol->protocol_mib, 0, &len, 0, 0) < 0)
		{
			LogDebugObjc(@"Warning: Unable to get sysctl length for name: %s\n", protocol->protocol_mib);
			continue;
		}
		
		char *buf;
        // allocate appropriate amount of memory
		if ((buf = malloc(len)) == 0)
		{
			LogDebugObjc(@"Error: Unable to allocate memory\n");
			[self setModuleStatus:NETWORKCONNECTIONS_STATUS_ERROR_UNABLE_TO_ALLOCATE_MEMORY];
			return FALSE;
		}
		
        // get sysctl data containing network connections information
		if (sysctlbyname(protocol->protocol_mib, buf, &len, 0, 0) < 0)
		{
			LogDebugObjc(@"Warning: Unable to get sysctl data for name: %s\n", protocol->protocol_mib);
			free(buf);
			continue;
		}
		
        // make sure data returned is large enough to be valid information
		if (len <= sizeof(struct xinpgen)) {
			LogDebugObjc(@"Protocol length too small\n");
            free(buf);
            continue;
        }
		
		struct xinpgen *xig = (struct xinpgen *)buf;
        
		//struct xtcpcb64 *tp = NULL;

        // xinpcb64 holds interface PCB information for OSX 10.6 and 10.7 and is defined in in_pcb.h
		struct xinpcb64 *inp;
        
        // xsocket64 holds socket information for OSX 10.6 and 10,7 and is defined in socketvar.h
		struct xsocket64 *socket;

		// for each data element in the network connections data returned by sysctl
		for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
			 xig->xig_len > sizeof(struct xinpgen);
			 xig = (struct xinpgen *)((char *)xig + xig->xig_len))
		{
            // if TCP
			if (protocol->protocol_ip == IPPROTO_TCP)
			{
                inp = &((struct xtcpcb64 *)xig)->xt_inpcb;
				socket = &inp->xi_socket;				
			}
			else 
			{
				inp = (struct xinpcb64 *)xig;
				socket = &inp->xi_socket;
			}
			
			if (socket->xso_protocol != (int)protocol->protocol_ip)
			{
				continue;
			}
			
            // build protocol name with version
			NSString *name = [NSString stringWithFormat:@"%s", protocol->protocol_name];
			if (inp->inp_vflag & INP_IPV4)
			{
				name = [name stringByAppendingFormat:@"4"];
			}
			if (inp->inp_vflag & INP_IPV6)
			{
				name = [name stringByAppendingFormat:@"6"];
			}
			
			[self xmlInsertStartTag:@"activeConnection" withLevel:2];
			
			LogDebugObjc(@"Name: %@\n", name);
			[self xmlInsertCompleteTag:@"connectionName" withLevel:3 withString:name];
			
			NSString *localAddress = @"*";
			NSString *foreignAddress = @"*";
			NSString *localPort = @"*";
			NSString *foreignPort = @"*";
			
            // for IPv4
			if (inp->inp_vflag & INP_IPV4)
			{
                // build local address and port if specified
				if (!(inp->inp_laddr.s_addr == INADDR_ANY))
				{
					localAddress = [NSString stringWithFormat:@"%u.%u.%u.%u", (inp->inp_laddr.s_addr) & 0xff,
									(inp->inp_laddr.s_addr >> 8) & 0xff,
									(inp->inp_laddr.s_addr >> 16) & 0xff,
									(inp->inp_laddr.s_addr >> 24) & 0xff];
				}
				if (inp->inp_lport != 0)
				{
					localPort= [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_lport)];
				}
				
				LogDebugObjc(@"Local: %@\n", localAddress);
				[self xmlInsertStartTag:@"localNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:localAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:localPort];
				[self xmlInsertEndTag:@"localNetworkAddress" withLevel:3];
				
                // build foreign address and port if specified
				if (!(inp->inp_faddr.s_addr == INADDR_ANY))
				{
					foreignAddress = [NSString stringWithFormat:@"%u.%u.%u.%u", (inp->inp_faddr.s_addr) & 0xff,
									  (inp->inp_faddr.s_addr >> 8) & 0xff,
									  (inp->inp_faddr.s_addr >> 16) & 0xff,
									  (inp->inp_faddr.s_addr >> 24) & 0xff];
				}
				if (inp->inp_fport != 0)
				{
					foreignPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_fport)];
				}
				
				LogDebugObjc(@"Foreign: %@\n", foreignAddress);
				[self xmlInsertStartTag:@"foreignNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:foreignAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:foreignPort];
				[self xmlInsertEndTag:@"foreignNetworkAddress" withLevel:3];
			}
            // for IPv6
			else if (inp->inp_vflag & INP_IPV6)
			{
                // local address and port
				if (!(IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)))
				{
					struct sockaddr_in6	lsin6;
					memset(&lsin6, 0, sizeof(lsin6));
					lsin6.sin6_len = sizeof(lsin6);
					lsin6.sin6_family = AF_INET6;
					lsin6.sin6_addr = inp->in6p_laddr;
					
					char lbuffer[NI_MAXHOST];
					getnameinfo((struct sockaddr *)&lsin6, lsin6.sin6_len, lbuffer, sizeof(lbuffer), NULL, 0, NI_NUMERICHOST);
					
					localAddress = [NSString stringWithFormat:@"%s", lbuffer];
				}
				if (inp->inp_lport != 0)
				{
					localPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_lport)];
				}
				
				LogDebugObjc(@"Local: %@\n", localAddress);
				[self xmlInsertStartTag:@"localNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:localAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:localPort];
				[self xmlInsertEndTag:@"localNetworkAddress" withLevel:3];

				// foreign address and port
				if (!(IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)))
				{
					struct sockaddr_in6	fsin6;
					memset(&fsin6, 0, sizeof(fsin6));
					fsin6.sin6_len = sizeof(fsin6);
					fsin6.sin6_family = AF_INET6;
					fsin6.sin6_addr = inp->in6p_faddr;
					
					char fbuffer[NI_MAXHOST];
					getnameinfo((struct sockaddr *)&fsin6, fsin6.sin6_len, fbuffer, sizeof(fbuffer), NULL, 0, NI_NUMERICHOST);
					
					foreignAddress = [NSString stringWithFormat:@"%s", fbuffer];
				}
				if (inp->inp_fport != 0)
				{
					foreignPort = [NSString stringWithFormat:@"%d", ntohs((u_short)inp->inp_fport)];
				}
				
				LogDebugObjc(@"Foreign: %@\n", foreignAddress);
				[self xmlInsertStartTag:@"foreignNetworkAddress" withLevel:3];
				[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:foreignAddress];
				[self xmlInsertCompleteTag:@"networkPortValue" withLevel:4 withString:foreignPort];
				[self xmlInsertEndTag:@"foreignNetworkAddress" withLevel:3];
			}
			
			[self xmlInsertEndTag:@"activeConnection" withLevel:2];
		}
		
		free(buf);
	}
	
	return TRUE;
}

- (Boolean)getRoutingTable
{
	size_t bufSize;
	int mibRouteTable[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP2, 0};
	char *buffer, *next, *limit;
	struct rt_msghdr2 *rtm;

    // use sysctl to get routing table information size
	if (sysctl(mibRouteTable, 6, NULL, &bufSize, NULL, 0) < 0)
	{
		LogDebugObjc(@"Error getting routing table information\n");
		return FALSE;
	}
	
	if ((buffer = malloc(bufSize)) == 0)
	{
		LogDebugObjc(@"Error occurred attempting to allocate memory\n");
		return FALSE;
	}
	
    // get routing table information
	if (sysctl(mibRouteTable, 6, buffer, &bufSize, NULL, 0) < 0)
	{
		LogDebugObjc(@"Error getting routing table\n");
		free(buffer);
		return FALSE;
	}
	
	[self xmlInsertStartTag:@"routingTableEntries" withLevel:1];
	
	limit = buffer + bufSize;
	for (next = buffer; next < limit; next += rtm->rtm_msglen)
	{
		rtm = (struct rt_msghdr2 *)next;
		struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
		struct sockaddr *sa_dest = nil;
		struct sockaddr *sa_gateway = nil;
		
		int family = sa->sa_family;
		
        // for now we are only interested in the Internet and Internet6 families
		if ((family == AF_INET) || (family == AF_INET6))
		{
			[self xmlInsertStartTag:@"routingTableEntry" withLevel:2];
			LogDebugObjc(@"Family: %s\n", (family == AF_INET ? "Internet" : "Internet6"));
			[self xmlInsertCompleteTag:@"networkFamily" withLevel:3 withString:[NSString stringWithFormat:@"%s", (family == AF_INET ? "Internet" : "Internet6")]];
			
			if (rtm->rtm_addrs & (1 << 0))
			{
				sa_dest = sa;
			}
			
			uint32_t offset;
			if (sa->sa_len > 0)
			{
				offset = 1 + (((uint32_t)sa->sa_len - 1) | ((uint32_t)sizeof(uint32_t) - 1));
			}
			else 
			{
				offset = sizeof(uint32_t);
			}
			
			sa = (struct sockaddr *)(offset + (char *)sa);
			if (rtm->rtm_addrs & (1 << 1))
			{
				sa_gateway = sa;
			}
			
			if (sa_dest)
			{
				LogDebugObjc(@"Getting destination information\n");
				[self xmlInsertStartTag:@"networkDestination" withLevel:3];
				
				if (sa_dest->sa_family == AF_INET)
				{
					struct sockaddr_in *sin = (struct sockaddr_in *)sa_dest;
					
					int iVal = sin->sin_addr.s_addr;
					NSString *inetValue = [NSString stringWithFormat:@"%d", (int)(iVal & 0xff)];
					int i;
					for (i = 0; i < 3; i++)
					{
						iVal = iVal >> 8;
						inetValue = [inetValue stringByAppendingFormat:@".%d", (int)(iVal & 0xff)];
					}
					LogDebugObjc(@"%@\n", inetValue);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:inetValue];
				}
				else if (sa_dest->sa_family == AF_INET6)
				{
					struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa_dest;
					char addressBuffer[513];
					int error = getnameinfo((struct sockaddr *)sin, sin->sin6_len, addressBuffer, sizeof(addressBuffer), NULL, 0, NI_NUMERICHOST|NI_WITHSCOPEID);
					
					if (error != 0)
					{
						inet_ntop(AF_INET6, &sin->sin6_addr, addressBuffer, sizeof(addressBuffer));
					}
					
					LogDebugObjc(@"%s\n", addressBuffer);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:[NSString stringWithFormat:@"%s", addressBuffer]];
				}
				[self xmlInsertEndTag:@"networkDestination" withLevel:3];
			}
			
			if (sa_gateway)
			{
				LogDebugObjc(@"Getting gateway information\n");
				[self xmlInsertStartTag:@"networkGateway" withLevel:3];
				
				if (sa_gateway->sa_family == AF_INET)
				{
					struct sockaddr_in *sin = (struct sockaddr_in *)sa_gateway;
					
					int iVal = sin->sin_addr.s_addr;
					NSString *inetValue = [NSString stringWithFormat:@"%d", (int)(iVal & 0xff)];
					int i;
					for (i = 0; i < 3; i++)
					{
						iVal = iVal >> 8;
						inetValue = [inetValue stringByAppendingFormat:@".%d", (int)(iVal & 0xff)];
					}
					LogDebugObjc(@"%@\n", inetValue);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:inetValue];
				}
				else if (sa_gateway->sa_family == AF_INET6)
				{
					struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa_gateway;
					char addressBuffer[513];
					int error = getnameinfo((struct sockaddr *)sin, sin->sin6_len, addressBuffer, sizeof(addressBuffer), NULL, 0, NI_NUMERICHOST|NI_WITHSCOPEID);
					
					if (error != 0)
					{
						inet_ntop(AF_INET6, &sin->sin6_addr, addressBuffer, sizeof(addressBuffer));
					}
					
					LogDebugObjc(@"%s\n", addressBuffer);
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:[NSString stringWithFormat:@"%s", addressBuffer]];
				}
				else if (sa_gateway->sa_family == AF_LINK)
				{
					NSString *linkAddress = @"";
					struct sockaddr_dl	*sdl = (struct sockaddr_dl *)sa_gateway;
					if (sdl->sdl_nlen == 0 && sdl->sdl_alen == 0 && sdl->sdl_slen == 0)
					{
						linkAddress = [NSString stringWithFormat:@"link#%d", sdl->sdl_index];
					}
					else 
					{
						if (sdl->sdl_type == IFT_ETHER)
						{
							int i;
							u_char *linkLayerAddr = (u_char *)sdl->sdl_data + sdl->sdl_nlen;
							
							NSString *delim = @"";
							for (i = 0; i < sdl->sdl_alen; i++, linkLayerAddr++) {
								linkAddress = [linkAddress stringByAppendingFormat:@"%@%x", delim, *linkLayerAddr];
								delim = @":";
							}
						}
						else 
						{
							linkAddress = [NSString stringWithFormat:@"%s", link_ntoa(sdl)];
						}
					}
					[self xmlInsertCompleteTag:@"networkAddressValue" withLevel:4 withString:linkAddress];
				}
				[self xmlInsertEndTag:@"networkGateway" withLevel:3];
			}
			
			[self xmlInsertEndTag:@"routingTableEntry" withLevel:2];
		}
	}
	
	[self xmlInsertEndTag:@"routingTableEntries" withLevel:1];

	return TRUE;
}

@end
