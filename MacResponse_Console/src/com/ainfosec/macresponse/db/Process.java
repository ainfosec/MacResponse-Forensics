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

public class Process extends TreeObject {
	public static final String[] columnNames = {
		"pid",
		"ppid",
		"processName"
	};
	
	public static final String[] columnTitles = {
		"Process ID",
		"Parent Process ID",
		"Process Name"
	};
	
	public String pid;
	public String ppid;
	public String processName;
	
	public ArrayList<CommandLineArg> commandLineArgs = new ArrayList<CommandLineArg>();
	public ArrayList<EnvironmentVariable> environmentVariables = new ArrayList<EnvironmentVariable>();
	public ArrayList<OpenFile> openFiles = new ArrayList<OpenFile>();
	
	public CommandLineArgsNode commandLineArgsNode = null;
	public EnvironmentVariablesNode environmentVariablesNode = null;
	public OpenFilesNode openFilesNode = null;
	public OpenConnectionsNode openConnectionsNode = null;
	
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
		return pid + " [" + processName + "]";
	}

	@Override
	public void init() {
		// Setup Children
		if(childObjects == null) {
			if(commandLineArgs != null) {
				if(commandLineArgsNode == null) {
					commandLineArgsNode = new CommandLineArgsNode();
					for(CommandLineArg cla : commandLineArgs) {
						commandLineArgsNode.addCommandLineArg(cla);
					}
				}
				addChildObject(commandLineArgsNode);
			}
			if(environmentVariables != null) {
				if(environmentVariablesNode == null) {
					environmentVariablesNode = new EnvironmentVariablesNode();
					// TODO Phenom errors when there's a commandlinearg in the environment variables
					try {
					for(EnvironmentVariable ev : environmentVariables) {
						environmentVariablesNode.addEnvironmentVariable(ev);
					}
					}catch (ClassCastException cce)
					{
						System.out.println("There's a command line arg in with the environment variables.");
					}
				}
				addChildObject(environmentVariablesNode);
			}
			if(openFiles != null) {
				if((openFilesNode == null) && (openConnectionsNode == null)) {
					for(OpenFile openFile : openFiles) {
						if(openFile.fileType.equals("IPv4") || openFile.fileType.equals("IPv6")) {
							if(openConnectionsNode == null) {
								openConnectionsNode = new OpenConnectionsNode();
							}
							openConnectionsNode.addOpenFile(openFile);
						}
						else {
							if(openFilesNode == null) {
								openFilesNode = new OpenFilesNode();
							}
							openFilesNode.addOpenFile(openFile);
						}
					}
				}
				addChildObject(openFilesNode);
				addChildObject(openConnectionsNode);
			}
		}
		
		// Setup Display Data
		// TODO Paul (Process Info, Command Line Args Table)
		if(displayData == null) {
			displayData = new DisplayData();
			ArrayList<TreeObject> list = new ArrayList<TreeObject>();
			list.add(this);
			displayData.addDisplayObject(new DisplayObject(getTitle(), columnTitles, columnNames, list));
			displayData.addDisplayObject(new DisplayObject("Command Line Arguments", CommandLineArg.columnTitles,CommandLineArg.columnNames, commandLineArgs));
		}
	}
}
