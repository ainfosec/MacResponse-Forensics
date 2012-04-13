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

public class AcquisitionImage extends TreeObject {

	// TODO remove unused fields
	
	public static final String[] columnNames = {
		"casePath", 
//		"imageFileName", 
//		"uncompressedImageSHA256Hash",
		"imageCompressed",
//		"compressedImageSHA256Hash",
		"acquisitionInterrupted"
	};

	public static final String[] columnTitles = {
		"Case Path", 
//		"Image File Name", 
//		"Uncompressed Image SHA256 Hash",
		"Image Compressed",
//		"Compressed Image SHA256 Hash",
		"Acquisition Interrupted"
	};

	public String casePath;
//	public String imageFileName;
	public String imageCompressed;
//	public String uncompressedImageSHA256Hash;
//	public String compressedImageSHA256Hash;
	public String acquisitionInterrupted;

	public ArrayList<AcquiredRegion> acquiredRegions = new ArrayList<AcquiredRegion>();
	
	@Override
	public String[] getColumnNames() {
		return columnNames;
	}

	@Override
	public String getTitle() {
		return "Acquisition Image";
	}

	@Override
	public void init() {
		// Child Objects
		if(childObjects == null && acquiredRegions != null) {
			for(TreeObject to : acquiredRegions) {
				addChildObject(to);
			}
		}
		
		// Display Data
		if(displayData == null) {
			// TODO Paul image info and acquired regions table
			displayData = new DisplayData();
			ArrayList<TreeObject> list = new ArrayList<TreeObject>();
			list.add(this);
			displayData.addDisplayObject(new DisplayObject(getTitle(), getColumnTitles(), getColumnNames(), list));
			displayData.addDisplayObject(new DisplayObject("Acquired Regions", AcquiredRegion.columnTitles, AcquiredRegion.columnNames, acquiredRegions));
		}
	}

	@Override
	public String[] getColumnTitles() {
		return columnTitles;
	}
}
