/*

 MacResponse: Incident Response Toolkit for Mac OS X

 Copyright (C) 2011 - Assured Information Security, Inc. All rights reserved.
 
 Authors:
 Paul Petzke <petzkep _at_ ainfosec.com>

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

package com.ainfosec.macresponse.db;


public class RootObject extends TreeObject
{
	@Override
	public String[] getColumnNames()
	{
		return null;
	}
	
	@Override
	public String[] getColumnTitles()
	{
		return null;
	}

	@Override
	public String getTitle() {
		return "Mac Response Modules";
	}

	@Override
	public void init() {
		// Child Objects
		// No init necessary
		
		// Display Data
		// None!
	}
}
