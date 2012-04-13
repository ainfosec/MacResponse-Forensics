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

public class PhysicalMemoryModule extends TreeObject {

	public AcquisitionImage acquisitionImage;

	public ArrayList<EfiMemoryRegion> efiMemoryRegions = new ArrayList<EfiMemoryRegion>();
	public EfiMemoryRegionNode efiMemoryRegionNode = null;

	@Override
	public String[] getColumnNames() {
		return AcquisitionImage.columnNames;
	}

	@Override
	public String[] getColumnTitles() {
		return AcquisitionImage.columnTitles;
	}

	@Override
	public String getTitle() {
		return "Physical Memory";
	}

	@Override
	public void init() {
		// Setup Children
		if(childObjects == null) {
			if(efiMemoryRegionNode == null) {
				efiMemoryRegionNode = new EfiMemoryRegionNode();
				for(EfiMemoryRegion emr : efiMemoryRegions) {
					efiMemoryRegionNode.addEfiMemoryRegion(emr);
				}
			}
			addChildObject(efiMemoryRegionNode);
			addChildObject(acquisitionImage);
		}
		
		// Setup Display Data
		if(displayData == null) {
			displayData = new DisplayData();
			ArrayList<AcquisitionImage> a = new ArrayList<AcquisitionImage>();
			a.add(acquisitionImage);
			displayData.addDisplayObject(new DisplayObject(getTitle(), AcquisitionImage.columnTitles, AcquisitionImage.columnNames, a));
		}
	}
}
