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

package com.ainfosec.macresponse.report;

import java.awt.Color;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.util.Date;

import org.eclipse.swt.SWT;

import com.ainfosec.macresponse.db.DisplayObject;
import com.ainfosec.macresponse.db.TreeObject;
import com.lowagie.text.Chapter;
import com.lowagie.text.Chunk;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.Paragraph;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.rtf.document.RtfDocument;
import com.lowagie.text.rtf.table.RtfTable;
import com.lowagie.text.rtf.text.RtfChapter;
import com.lowagie.text.rtf.text.RtfParagraph;

public class RtfGenerator {

	private static int currentChapter = 1;
	
	private static Font chapterTitleFont = new Font(Font.TIMES_ROMAN, 18, Font.BOLD);
	private static Font sectionTitleFont = new Font(Font.TIMES_ROMAN, 16, Font.BOLD);
	private static Font contentFont = new Font(Font.TIMES_ROMAN, 12, Font.NORMAL);
	
	private static RtfDocument document = null;
	
	// iText allows to add metadata to the PDF which can be viewed in your Adobe
	// Reader
	// under File -> Properties
	private static void addMetaData(String caseName, String authorName) {
		// TODO Paul able to do this?
//		document.addTitle(caseName);
//		document.addSubject("MacResponse Console");
//		document.addKeywords("");
//		document.addAuthor(authorName);
//		document.addCreator(System.getProperty("user.name"));
	}

	private static void addTitlePage() {
		Paragraph preface = new Paragraph();
		// We add one empty line
		preface.add(Chunk.NEWLINE);
		// Lets write a big header
		preface.add(new Paragraph("MAC Response", chapterTitleFont));

		preface.add(Chunk.NEWLINE);
		// Will create: Report generated by: _name, _date
		preface.add(new Paragraph(
				"Report generated by: " + System.getProperty("user.name") + ", " + new Date(), //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				contentFont));
		preface.add(Chunk.NEWLINE);
		preface.add(Chunk.NEWLINE);
		preface.add(Chunk.NEWLINE);
		preface.add(new Paragraph(
				"This document describes something which is very important ",
				contentFont));

		document.add(new RtfParagraph(document, preface));
		// Start a new page
		// TODO Paul do this again
		//document.newPage();
	}
	
	private static void addTables(TreeObject rootObject) {
		// TODO Paul add table of contents/etc.?
		// Table of Contents
		//document.add(new RtfTableOfContents("Table of Contents2"));
		Paragraph paragraph = new Paragraph();
		paragraph.add("Table of Contents\n\n");
		
		for(TreeObject treeObject : rootObject.getChildObjects()) {
			if(treeObject.isChecked()) {
				addTocSection(paragraph, treeObject, String.valueOf(currentChapter));
				currentChapter++;
			}
		}
		currentChapter = 1;
		
		document.add(new RtfParagraph(document, paragraph));
		
		// Table of Figures
		// Table of Tables
	}
	
	private static void addTocSection(Paragraph paragraph, TreeObject treeObject, String sectionNumber) {
		int subsectionNumber = 1;
		
		if(treeObject.isChecked()) {
			StringBuffer sb = new StringBuffer();
			sb.append(sectionNumber);
			sb.append(". ");
			sb.append(treeObject.getTitle());
			sb.append("\n");
			paragraph.add(sb.toString());
		}
		
		// TODO Paul Print out the data sections
		
		// Print out the children
		if((treeObject.getChildObjects() != null) && (treeObject.getChildObjects().size() > 0)) {
			for(TreeObject childObject : treeObject.getChildObjects()) {
				String currentSection = sectionNumber + "." + String.valueOf(subsectionNumber);
				if(treeObject.isChecked()) {
					addTocSection(paragraph, childObject, currentSection);
					subsectionNumber++;
				}
			}
		}
	}

	private static void addContent(TreeObject rootObject) {
		for(TreeObject treeObject : rootObject.getChildObjects()) {
			if(treeObject.isChecked()) {
				Paragraph title = new Paragraph(treeObject.getTitle(), chapterTitleFont);
				Chapter chapter = new Chapter(title, currentChapter);
				populateChapter(treeObject, chapter);
				document.add(new RtfChapter(document, chapter));
				currentChapter++;
			}
		}
	}

	private static void populateChapter(TreeObject treeObject, Chapter chapter) {
		// If there are children, don't display this object's data
		if((treeObject.getChildObjects() == null) || (treeObject.getChildObjects().size() == 0)) {
			// Create the Data Paragraphs (displayObjects)
			if((treeObject.getDisplayData() != null) && (treeObject.getDisplayData().getDisplayObjects() != null)) {
				for(DisplayObject displayObject : treeObject.getDisplayData().getDisplayObjects()) {
					Paragraph paragraph = new Paragraph(displayObject.getTitle(), sectionTitleFont);

					paragraph.add("\n");
					createDataSection(paragraph, displayObject);
					
					chapter.addSection(paragraph);
				}
			}
		}
		// If there are children, display them
		else {
			for(TreeObject childTreeObject : treeObject.getChildObjects()) {
				Paragraph title = new Paragraph(childTreeObject.getTitle(), sectionTitleFont);
				Paragraph content = new Paragraph("\n");

				generateData(content, childTreeObject);
				
				chapter.addSection(title);
				chapter.add(content);
			}
		}
	}
	
	private static void generateData(Paragraph paragraph, TreeObject treeObject) {
		// TODO Paul take into consideration TreeObjects that have children (don't display current, make a section for each child)
		
		for(DisplayObject displayObject : treeObject.getDisplayData().getDisplayObjects()) {
			createDataSection(paragraph, displayObject);
			paragraph.add("\n");
		}
	}
	
	private static void createDataSection(Paragraph paragraph, DisplayObject displayObject) {
		if(displayObject == null || displayObject.getObjects() == null) {
			return;
		}
		
		// See if the DisplayObject has a list or a single object
		if(displayObject.getObjects().size() == 1) {
			TreeObject treeObject = displayObject.getObjects().get(0);	// There's only 1 item

			// For each column, create/add a label with the title and the data
			int i = 0;
			for(String columnName : displayObject.getColumnNames()) {
				StringBuffer sb = new StringBuffer();
				
				// Add the column title
				sb.append(displayObject.getColumnTitles()[i]);
				sb.append(": ");
				
				// Get the value of the field
				try {
					Field field = treeObject.getClass().getDeclaredField(columnName);
					String val = (String)field.get(treeObject);
					if(val == null)
					{
						val = "";
					}
					// Add the value
					sb.append(val);
					sb.append("\n");
				} catch (NoSuchFieldException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalAccessException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				// Put the string into the paragraph
				paragraph.add(sb.toString());
				i++;
			}
		}
		else {
			PdfPTable table = new PdfPTable(displayObject.getColumnTitles().length);
	        table.setWidthPercentage(100);
	        table.setHorizontalAlignment(Element.ALIGN_CENTER);

			for(String columnName : displayObject.getColumnTitles()) {
		        table.getDefaultCell().setBackgroundColor(Color.CYAN);
				table.addCell(columnName);
		        table.getDefaultCell().setBackgroundColor(Color.WHITE);
			}

			for(TreeObject to1 : displayObject.getObjects())
			{
				for(String columnName : displayObject.getColumnNames()) {
					try {
						Field field = to1.getClass().getDeclaredField(columnName);
						String val = (String)field.get(to1);
						if(val == null)
						{
							val = "";
						}
						table.addCell(val);
					} catch (NoSuchFieldException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
	        table.getDefaultCell().setColspan(displayObject.getColumnTitles().length);
	        table.getDefaultCell().setBorder(SWT.NONE);
	        table.getDefaultCell().setHorizontalAlignment(Element.ALIGN_CENTER);
	        
	        // TODO Paul number the tables
			table.addCell("Table: " + displayObject.getTitle());
			document.add(new RtfTable(document, table));
		}
	}

	public static void generateReport(String filename, TreeObject rootObject) {
		if((rootObject == null) || (filename == null)) {
			return;
		}
		try {
			document = new RtfDocument();
			document.open();
			//document.setMargins(20f, 20f, 20f, 20f);
			addMetaData("CASEID", "AUTHOR");
			addTitlePage();
			addTables(rootObject);
			addContent(rootObject);
			document.writeDocument(new FileOutputStream(filename));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
