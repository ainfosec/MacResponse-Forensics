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

public abstract class TreeObject {
	protected TreeObject parentObject = null;
	protected ArrayList<TreeObject> childObjects = null;
	protected DisplayData displayData = null;
	
	protected boolean isChecked = false;
	
	public void setChecked(boolean value) {
		isChecked = value;
		if(childObjects != null) {
			for(TreeObject child : childObjects) {
				child.setChecked(value);
			}
		}
	}
	
	public boolean isChecked() {
		return isChecked;
	}

	public void setParent(TreeObject parentObject) {
		this.parentObject = parentObject;
	}

	public TreeObject getParentObject() {
		return parentObject;
	}

	public void addChildObject(TreeObject to) {
		if(to == null) {
			return;
		}
		if (childObjects == null) {
			childObjects = new ArrayList<TreeObject>();
		}
		to.setParent(this);
		to.init();
		childObjects.add(to);
	}

	public DisplayData getDisplayData() {
		init();
		return displayData;
	}

	public ArrayList<? extends TreeObject> getChildObjects() {
		init();
		return childObjects;
	}

	public abstract String getTitle();

	public abstract String[] getColumnNames();
	
	public abstract String[] getColumnTitles();
	
	public abstract void init();
}
