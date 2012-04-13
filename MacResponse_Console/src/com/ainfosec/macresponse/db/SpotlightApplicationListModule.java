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

public class SpotlightApplicationListModule extends TreeObject {
	protected String treeNodeTitle = "Spotlight Application List Module";
	
	public ArrayList<Application> applications = new ArrayList<Application>();
	private BinaryNode binaryChild = null;
	private ApplicationNode applicationChild = null;
	
	public String[] getColumnNames() {
		return Application.columnNames;
	}

	@Override
	public String[] getColumnTitles() {
		return Application.columnTitles;
	}

	@Override
	public String getTitle() {
		return "Spotlight Application List";
	}

	@Override
	public void init() {
		// Setup Children
		if(childObjects == null) {
			if(binaryChild == null) {
				binaryChild = new BinaryNode();
				for(Application app : applications) {
					if(app.applicationType.equals("binary")) {
						binaryChild.addTableObject(app);
					}
				}
				this.addChildObject(binaryChild);
			}
			if(applicationChild == null) {
				applicationChild = new ApplicationNode();
				for(Application app : applications) {
					if(app.applicationType.equals("application")) {
						applicationChild.addTableObject(app);
					}
				}
				this.addChildObject(applicationChild);
			}
		}
		
		// Setup Display Data
		if(displayData == null) {
			displayData = new DisplayData();
			displayData.addDisplayObject(new DisplayObject(getTitle(), Application.columnTitles, Application.columnNames, applications));
		}
	}
}
