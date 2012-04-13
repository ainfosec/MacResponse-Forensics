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


public class EfiMemoryRegion extends TreeObject {
	public static final String[] columnNames = {
		"physicalAddressStart", 
		"physicalAddressEnd", 
		"efiMemoryRegionType", 
		"rangeIsDRAM", 
	}; 
	public static final String[] columnTitles = {
		"Physical Address Start", 
		"Physical Address End", 
		"EFI Memory Region Type", 
		"Range Is DRAM?", 
	}; 

	public String physicalAddressStart;
	public String physicalAddressEnd;
	public String efiMemoryRegionType;
	public String rangeIsDRAM;

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
		return null;
	}

	@Override
	public void init() {
		// Child Objects
		// None!
		
		// Display Data
		// None!
	}
}
