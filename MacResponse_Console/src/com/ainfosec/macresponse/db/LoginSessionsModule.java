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

public class LoginSessionsModule extends TreeObject {
	public ArrayList<LoginSession> loginSessions = new ArrayList<LoginSession>();
	
	public String[] getColumnNames() {
		return LoginSession.columnNames;
	}
	
	public String[] getColumnTitles() {
		return LoginSession.columnTitles;
	}

	@Override
	public String getTitle() {
		return "Login Session";
	}

	@Override
	public ArrayList<? extends TreeObject> getChildObjects() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init() {
		// Setup Children
		// None!
		
		// Setup Display Data
		if(displayData == null) {
			displayData = new DisplayData();
			displayData.addDisplayObject(new DisplayObject(getTitle(), LoginSession.columnTitles, LoginSession.columnNames, loginSessions));
		}
	}
}
