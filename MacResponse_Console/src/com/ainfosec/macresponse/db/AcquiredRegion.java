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

import java.util.ArrayList;

public class AcquiredRegion extends TreeObject {
	public static final String[] columnNames = {
		"physicalAddressStart", 
		"physicalAddressEnd", 
		"fileOffsetStart", 
		"fileOffsetEnd", 
	};
	
	public static final String[] columnTitles = {
		"Physical Address Start", 
		"Physical Address End", 
		"File Offset Start", 
		"File Offset End", 
	};

	public String physicalAddressStart;
	public String physicalAddressEnd;
	public String fileOffsetStart;
	public String fileOffsetEnd;	

	public ArrayList<UnmappablePage> unmappablePages = new ArrayList<UnmappablePage>();
	
	@Override
	public String[] getColumnNames() {
		return columnNames;
	}

	@Override
	public String getTitle() {
		return physicalAddressStart + "-" + physicalAddressEnd;
	}

	@Override
	public void init() {
		// Setup Children
		if((childObjects == null) && (unmappablePages != null)) {
			for(TreeObject to : unmappablePages) {
				addChildObject(to);
			}
		}
		
		// Setup Display Data
		if(displayData == null) {
			displayData = new DisplayData();
			ArrayList<TreeObject> list = new ArrayList<TreeObject>();
			list.add(this);
			displayData.addDisplayObject(new DisplayObject(getTitle(), columnTitles, columnNames, list));
		}
	}

	@Override
	public String[] getColumnTitles() {
		return columnTitles;
	}
}
