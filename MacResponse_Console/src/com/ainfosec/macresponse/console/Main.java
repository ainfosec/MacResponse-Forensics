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

package com.ainfosec.macresponse.console;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;

import org.eclipse.swt.widgets.Display;

import com.ainfosec.macresponse.console.ui.CasePathShell;
import com.ainfosec.macresponse.console.ui.MacResponseShell;
import com.ainfosec.macresponse.db.AcquiredRegion;
import com.ainfosec.macresponse.db.AcquisitionImage;
import com.ainfosec.macresponse.db.ActiveConnection;
import com.ainfosec.macresponse.db.Application;
import com.ainfosec.macresponse.db.CaseLogModule;
import com.ainfosec.macresponse.db.CommandLineArg;
import com.ainfosec.macresponse.db.Dependency;
import com.ainfosec.macresponse.db.DiskInformationModule;
import com.ainfosec.macresponse.db.Driver;
import com.ainfosec.macresponse.db.DriverInformationModule;
import com.ainfosec.macresponse.db.EfiMemoryRegion;
import com.ainfosec.macresponse.db.EnvironmentVariable;
import com.ainfosec.macresponse.db.FilePathInfo;
import com.ainfosec.macresponse.db.FileVaultLoggedInUser;
import com.ainfosec.macresponse.db.FileVaultModule;
import com.ainfosec.macresponse.db.FilesystemInformationModule;
import com.ainfosec.macresponse.db.ForeignNetworkAddress;
import com.ainfosec.macresponse.db.LocalNetworkAddress;
import com.ainfosec.macresponse.db.LogMessage;
import com.ainfosec.macresponse.db.LoginSession;
import com.ainfosec.macresponse.db.LoginSessionsModule;
import com.ainfosec.macresponse.db.MountedDisk;
import com.ainfosec.macresponse.db.NetworkAddress;
import com.ainfosec.macresponse.db.NetworkConfigurationModule;
import com.ainfosec.macresponse.db.NetworkConnectionsModule;
import com.ainfosec.macresponse.db.NetworkInterface;
import com.ainfosec.macresponse.db.NetworkInterfaceFlag;
import com.ainfosec.macresponse.db.OpenFile;
import com.ainfosec.macresponse.db.PhysicalMemoryModule;
import com.ainfosec.macresponse.db.Process;
import com.ainfosec.macresponse.db.ProcessInformationModule;
import com.ainfosec.macresponse.db.PropertyList;
import com.ainfosec.macresponse.db.PropertyListsModule;
import com.ainfosec.macresponse.db.RootObject;
import com.ainfosec.macresponse.db.RoutingTableEntry;
import com.ainfosec.macresponse.db.ScreenshotModule;
import com.ainfosec.macresponse.db.SpotlightApplicationListModule;
import com.ainfosec.macresponse.db.SystemConfigFile;
import com.ainfosec.macresponse.db.SystemControlItem;
import com.ainfosec.macresponse.db.SystemDateTimeModule;
import com.ainfosec.macresponse.db.SystemInformationModule;
import com.ainfosec.macresponse.db.SystemStartupItem;
import com.ainfosec.macresponse.db.TreeObject;
import com.ainfosec.macresponse.db.UnmappablePage;
import com.ainfosec.macresponse.db.User;
import com.ainfosec.macresponse.db.UserInformationModule;
import com.thoughtworks.xstream.XStream;

/**
 * TODO javadoc
 * @author paulpetzke
 *
 */
public class Main {
	
	/**
	 * TODO javadoc
	 * @param args
	 */
    public static void main(String[] args) {
        // The display
    	Display display = new Display();

		// Get the Case Path
		CasePathShell cps = new CasePathShell(display);
		String casePath = cps.getCasePath();
		if(casePath == null || casePath.equals("")) {
			System.out.println("Invalid Case Path");
			System.exit(1);
		}
		if(!casePath.endsWith("/"))
		{
			casePath = casePath + "/";
		}
		// Test that the file exists
		File file = new File(casePath);
		if (!file.exists()) {
			System.out.println("Error getting the case path!");
			System.exit(1);
		}

		// Get the ApplicationListModule data
		XStream xstream = new XStream();
		
		xstream.alias("CaseLog", CaseLogModule.class);
		xstream.alias("logMessage", LogMessage.class);
		
		xstream.alias("DiskInformationModule", DiskInformationModule.class);
		xstream.alias("mountedDisk", MountedDisk.class);
		
		xstream.alias("DriverInformationModule", DriverInformationModule.class);
		xstream.alias("driver", Driver.class);
		xstream.alias("dependency", Dependency.class);
		
		xstream.alias("FilesystemInformationModule", FilesystemInformationModule.class);
		xstream.alias("filePathInfo", FilePathInfo.class);
		xstream.alias("filePath", String.class);
		xstream.alias("fileStat", String.class);
			
		xstream.alias("FileVaultModule", FileVaultModule.class);
		xstream.alias("fileVaultLoggedInUser", FileVaultLoggedInUser.class);
		
		xstream.alias("LoginSessionsModule", LoginSessionsModule.class);
		xstream.alias("loginSession", LoginSession.class);

		xstream.alias("NetworkConfigurationModule", NetworkConfigurationModule.class);
		xstream.alias("networkInterface", NetworkInterface.class);
		xstream.alias("networkAddress", NetworkAddress.class);
		xstream.alias("networkInterfaceFlag", NetworkInterfaceFlag.class);
		xstream.alias("networkInterface", NetworkInterface.class);
		
		xstream.alias("NetworkConnectionsModule", NetworkConnectionsModule.class);
		xstream.alias("activeConnection", ActiveConnection.class);
		xstream.alias("localNetworkAddress", LocalNetworkAddress.class);
		xstream.alias("foreignNetworkAddress", ForeignNetworkAddress.class);
		xstream.alias("routingTableEntry", RoutingTableEntry.class);
		
		xstream.alias("ProcessInformationModule", ProcessInformationModule.class);
		xstream.alias("process", Process.class);
		xstream.alias("openFile", OpenFile.class);
		xstream.alias("commandLineArg", CommandLineArg.class);
		xstream.alias("environmentVariable", EnvironmentVariable.class);
		
		xstream.alias("PhysicalMemoryModule", PhysicalMemoryModule.class);
		xstream.alias("efiMemoryRegion", EfiMemoryRegion.class);
		xstream.alias("acquisitionImage", AcquisitionImage.class);
		xstream.alias("acquiredRegion", AcquiredRegion.class);
		xstream.alias("unmappablePage", UnmappablePage.class);
		
		xstream.alias("PropertyListsModule", PropertyListsModule.class);
		xstream.alias("propertyList", PropertyList.class);
		
		xstream.alias("ScreenshotModule", ScreenshotModule.class);
		
		xstream.alias("SpotlightApplicationListModule", SpotlightApplicationListModule.class);
		xstream.alias("application", Application.class);
		
		xstream.alias("SystemDateTimeModule", SystemDateTimeModule.class);
		
		xstream.alias("SystemInformationModule", SystemInformationModule.class);
		xstream.alias("systemControlItem", SystemControlItem.class);
		xstream.alias("systemConfigFile", SystemConfigFile.class);
		xstream.alias("systemStartupItem", SystemStartupItem.class);
		
		xstream.alias("UserInformationModule", UserInformationModule.class);
		xstream.alias("user", User.class);
		
		String moduleXMLFileNames[] = {
				"CaseLog.xml",
				"DiskInformation.xml",
				"DriverInformation.xml",
//				"FilesystemInformation.xml",
				"FileVault.xml",
				"LoginSessions.xml",
				"NetworkConfiguration.xml",
				"NetworkConnections.xml",
				"PhysicalMemory.xml",
				"ProcessInformation.xml",
				"PropertyLists.xml",
				"Screenshot.xml",
				"SpotlightApplicationList.xml",
				"SystemDateTime.xml",
				"SystemInformation.xml",
				"UserInformation.xml",
		};

		RootObject baseObject = new RootObject();
		baseObject.init();
		for (String xmlFileName : moduleXMLFileNames) {
			TreeObject moduleRoot = null;
			FileInputStream fs = null;
			
			try {
				fs = new FileInputStream(casePath + xmlFileName);
				moduleRoot = (TreeObject) xstream.fromXML(fs);
				moduleRoot.init();
				baseObject.addChildObject(moduleRoot);
				fs.close();
			} catch (FileNotFoundException e) {
				// This can occur when a run hasn't been done (no file)
				continue;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		// Do FilesystemInformation (it's too big to do the same as the rest)
		String xmlFileName = "FilesystemInformation.xml";
		FilesystemInformationModule filesystemInfoModule = null;
		FileInputStream fs = null;
		
		try {
			fs = new FileInputStream(casePath + xmlFileName);
			// FIXME(petzkep) quick work-around to skip the first two lines of
			// the file
			int skipLength = 0;
			BufferedReader br = new BufferedReader(new FileReader(casePath
					+ xmlFileName));
			String line = br.readLine();
			skipLength += line.length();
			++skipLength; // The newline char
			line = br.readLine();
			skipLength += line.length();
			++skipLength; // The newline char
			br.close();
			

			filesystemInfoModule = new FilesystemInformationModule();
			fs.skip(skipLength);
			ObjectInputStream ois = xstream.createObjectInputStream(fs);
			// FIXME(petzkep) Limited to 50k because of outputting to pdf.
			// 200k works if viewing
			for (int i = 0; i < 50000; ++i) {
				FilePathInfo child = (FilePathInfo) ois.readObject();
				filesystemInfoModule.filePathInfos.add(child);
			}
			ois.close();
			fs.close();
			

			filesystemInfoModule.init();
			baseObject.addChildObject(filesystemInfoModule);
		} catch (FileNotFoundException e) {
			// if it doesn't exist, don't do anything with it
		} catch (EOFException e) {
			// TODO Auto-generated catch block
			// FIXME(petzkep)
			// Do nothing, this is currently how we tell it's done!
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
        // Start MacResponseShell
        new MacResponseShell(display, baseObject);
        
        // If it ends, dispose the display
        display.dispose();
    }
}
