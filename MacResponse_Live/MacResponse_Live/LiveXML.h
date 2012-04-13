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
#import "LiveFile.h"

@interface LiveXML : NSObject {
	LiveFile *xmlLiveFile;
}


- (LiveXML *)init;

- (Boolean)open:(NSString *)filePath;

+ (LiveXML *)allocLiveXMLWith:(NSString *)filePath;

- (void)writeString:(NSString *)str;

- (void)insertTabs:(UInt32)level;

- (void)insertStartTag:(NSString *)tagName withLevel:(UInt32)level;

- (void)insertEndTag:(NSString *)tagName withLevel:(UInt32)level;

- (void)insertCompleteTag:(NSString *)tagName withLevel:(UInt32)level withString:(NSString *)dataString;

- (void) close;

@end
