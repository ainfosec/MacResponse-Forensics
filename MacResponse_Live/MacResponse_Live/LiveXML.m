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


#import "LiveXML.h"
#import "LiveLog.h"

@implementation LiveXML

- (LiveXML *)init
{
	self = [super init];
	
	return self;
}

- (Boolean)open:(NSString *)filePath
{	
	xmlLiveFile = [LiveFile allocLiveFileCreate:filePath withCompression:FALSE];
	
	NSString *xmlTag = @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
	NSData *data = [xmlTag dataUsingEncoding:NSUTF8StringEncoding];
	
	return [xmlLiveFile write:data];	
}

+ (LiveXML *)allocLiveXMLWith:(NSString *)filePath
{
	LiveXML *lx = [[LiveXML alloc] init];
	if ([lx open:filePath]) 
	{
		return lx;
	}
	
	[lx release];
	return nil;
}

- (NSMutableString *)sanatizeXmlString:(NSString *)xmlString
{    
    NSMutableString *newXmlString = [[xmlString mutableCopy] autorelease];
    
    [newXmlString replaceOccurrencesOfString:@"<" withString:@"&lt;"
                                   options:NSLiteralSearch
                                     range:NSMakeRange(0, [xmlString length])];
    
    [newXmlString replaceOccurrencesOfString:@">" withString:@"&gt;"
                                     options:NSLiteralSearch
                                       range:NSMakeRange(0, [xmlString length])];
    
    [newXmlString replaceOccurrencesOfString:@"&" withString:@"&amp;"
                                     options:NSLiteralSearch
                                       range:NSMakeRange(0, [xmlString length])];
    
    [newXmlString replaceOccurrencesOfString:@"\"" withString:@"&quot;"
                                     options:NSLiteralSearch
                                       range:NSMakeRange(0, [xmlString length])];
    
    [newXmlString replaceOccurrencesOfString:@"\\" withString:@"&apos;"
                                     options:NSLiteralSearch
                                       range:NSMakeRange(0, [xmlString length])];
    
    return newXmlString;
    
}

- (void)writeString:(NSString *)str
{
	NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];	
	[xmlLiveFile write:data];
}

- (void)insertTabs:(UInt32)level
{
	while (level--)
	{
		[self writeString:@"\t"];
	}
}

- (void)insertStartTag:(NSString *)tagName withLevel:(UInt32)level
{
	[self insertTabs:level];
	[self writeString:[NSString stringWithFormat:@"<%@>\n", tagName]];
}

- (void)insertEndTag:(NSString *)tagName withLevel:(UInt32)level
{
	[self insertTabs:level];
	[self writeString:[NSString stringWithFormat:@"</%@>\n", tagName]];	
}

- (void)insertCompleteTag:(NSString *)tagName withLevel:(UInt32)level withString:(NSString *)dataString 
{
    NSMutableString *sanitizedDataString = [self sanatizeXmlString:dataString];
    
	[self insertTabs:level];
	[self writeString:[NSString stringWithFormat:@"<%@>%@</%@>\n", tagName, sanitizedDataString, tagName]];
}

- (void) close
{
	[xmlLiveFile close];
	
	LogDebugObjc(@"XML Hash: %@\n", [xmlLiveFile outputDataHashSHA256]);
	
	[xmlLiveFile release];
}

@end
