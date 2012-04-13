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

public class SystemInformationModule extends TreeObject {
	public ArrayList<SystemControlItem> systemControlItems = new ArrayList<SystemControlItem>();
	public ArrayList<SystemConfigFile> systemConfigFiles;
	public ArrayList<SystemStartupItem> systemStartupItems = new ArrayList<SystemStartupItem>();

	public static final String[] columnNames = {
		"systemControlItems",
		"systemConfigFiles",
		"systemStartupItems"
	};

	public static final String[] columnTitles = {
		"System Control Items",
		"System Config Files",
		"System Startup Items"
	};
	
	@Override
	public String[] getColumnNames() {
		return columnNames;
	}
	
	@Override
	public String[] getColumnTitles() {
		return columnTitles;
	}

	@Override
	public String getTitle() {
		return "System Information";
	}

	@Override
	public void init() {
		// Setup Children
		// None
		
		// Setup Display Data
		// TODO(Paul) will want to add system config files and startup items
		if(displayData == null) {
			displayData = new DisplayData();
			ArrayList<TreeObject> list = new ArrayList<TreeObject>();
			list.add(this);
			displayData.addDisplayObject(new DisplayObject(getTitle(), SystemControlItem.columnTitles, SystemControlItem.columnNames, systemControlItems));
		}
	}
}
