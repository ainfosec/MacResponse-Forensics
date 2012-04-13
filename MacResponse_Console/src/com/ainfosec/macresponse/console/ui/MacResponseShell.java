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

package com.ainfosec.macresponse.console.ui;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.SashForm;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Point;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowData;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.ScrollBar;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.widgets.TreeItem;

import com.ainfosec.macresponse.db.DisplayObject;
import com.ainfosec.macresponse.db.TreeObject;
import com.ainfosec.macresponse.report.PdfGenerator;

/**
 * This class is the Mac Response GUI that is displayed.
 */
public class MacResponseShell implements Listener {
	/** The shell that the Display object opens. Everything is added to this shell */
	private Shell shell = null;
	
	// Menu Bar Items
	private Menu rootMenu = null;
	// The File Menu
	private Menu fileMenu = null;
	private MenuItem fileMenuItem = null;
	private MenuItem exportPdfMenuItem = null;

	private SashForm leftSashForm;
	private SashForm rightSashForm;

	/** The current table being displayed on the right */
	private ArrayList<Composite> currentComposites = new ArrayList<Composite>();

	/** The Tree on the left panel */
	private Tree tree = null;
	/** The Items in the Tree (parsed via rootObject.getObjects()) */
	private TreeObject rootObject;

	/** A HashMap of the TreeObjects that correspond to each TreeItem in the Tree */
	private HashMap<TreeItem, TreeObject> treeObjects = new HashMap<TreeItem, TreeObject>();

	/**
	 * The Constructor which will create the shell and open it on
	 * the Display object passed in.
	 * @param display The Display to use.
	 * @param rootObject The root to the TreeObjects to display.
	 */
	public MacResponseShell(Display display, TreeObject rootObject)
	{
		// Setup the base shell
		shell = new Shell(display);
		this.rootObject = rootObject;
		shell.setText("MacResponse LE\u2122: Analysis Console");

		// setup the UI
		initUI();

		// final setups
		shell.setMaximized(true);

		// Open the base shell
		shell.open();

		// Keep it alive
		while(!shell.isDisposed())
		{
			if(!display.readAndDispatch())
			{
				display.sleep();
			}
		}
	}

	/**
	 * Sets up the interface.
	 */
	private void initUI()
	{
		createMenu();
		
		// The Layout
		GridLayout gridLayout = new GridLayout();
		gridLayout.numColumns = 1;
		shell.setLayout(gridLayout);

		// The Information Composite
		SashForm sashForm = new SashForm(shell, SWT.PUSH);
		GridData gridData = new GridData(GridData.FILL_BOTH);
		sashForm.setLayoutData(gridData);
		leftSashForm = new SashForm(sashForm, SWT.CENTER);
		rightSashForm = new SashForm(sashForm, SWT.CENTER);
		sashForm.setWeights(new int[]{1, 4});
		
		// The status bar
		Label label = new Label(shell, SWT.PUSH);
		label.setText("Assured Information Security, Inc. (www.ainfosec.com)");
		GridData gridData2 = new GridData(GridData.FILL_HORIZONTAL);
		gridData2.horizontalAlignment = GridData.CENTER;
		label.setLayoutData(gridData2);

		// Tree Pane
		tree = new Tree(leftSashForm, SWT.BORDER | SWT.CHECK);
		populateTree(tree);
		tree.addListener(SWT.Selection, this);
	}

	/**
	 * Populate the Drop-down Menus.
	 */
	private void createMenu() {
		// The Menu Bar
		rootMenu = new Menu(shell, SWT.BAR);
		shell.setMenuBar(rootMenu);
		
		// The File Menu
		fileMenuItem = new MenuItem(rootMenu, SWT.CASCADE);
		fileMenuItem.setText("&File");
		fileMenu = new Menu(shell, SWT.DROP_DOWN);
		fileMenuItem.setMenu(fileMenu);
		exportPdfMenuItem = new MenuItem(fileMenu, SWT.PUSH);
		exportPdfMenuItem.setText("E&xport PDF");
		exportPdfMenuItem.addListener(SWT.Selection, this);
	}

	/**
	 * Populate the items in the tree
	 * @param tree The tree to fill.
	 */
	private void populateTree(Tree tree)
	{
		TreeItem rootItem = new TreeItem(tree, SWT.None);
		// TODO Paul make this expanded by default
		rootItem.setText("Mac Response");
		treeObjects.put(rootItem, rootObject);
		populateTreeItem(rootItem, rootObject);
	}

	/**
	 * For treeItem, fill in the children
	 * @param treeItem
	 * @param dbo
	 */
	private void populateTreeItem(TreeItem treeItem, TreeObject dbo)
	{
		if(dbo == null || dbo.getChildObjects() == null || dbo.getChildObjects().size() == 0) {
			return;
		}

		for(TreeObject dbo1: dbo.getChildObjects())
		{
			TreeItem item = new TreeItem(treeItem, SWT.NONE);
			if(dbo1.getTitle() == null) {
				item.setText("null");
				System.out.println("null tree node title: " + dbo1.getClass().getSimpleName());
			}
			else {
				item.setText(dbo1.getTitle());
			}
			if(treeObjects.containsKey(item))
			{
				System.out.println("Contains key, oh no!");
			}
			treeObjects.put(item, dbo1);
			populateTreeItem(item, dbo1);
		}
	}

	@Override
	public void handleEvent(Event event) {
		// Handle Menu events
		if(event.widget instanceof MenuItem) {
			// Export PDF
			if(event.widget == exportPdfMenuItem) {
				exportPdf();
			}
		}
		// Handle checking an item's TreeItem
		else if(event.detail == SWT.CHECK) {
			TreeItem treeItem = (TreeItem)event.item;
			recurseCheckTreeItem(treeItem, treeItem.getChecked());
		}
		// Handle Tree Selections
		else if(event.item instanceof TreeItem) {
			TreeItem treeItem = (TreeItem)event.item;

			// The Tree Object
			TreeObject to = treeObjects.get(treeItem);
			if(to == null) {
				System.out.println("to was null!");
				return;
			}
			if(to.getDisplayData() == null) {
				return;
			}
			while(currentComposites.size() != 0) {
				currentComposites.get(0).dispose();
				currentComposites.remove(0);
			}
			updateDisplay(to);
			rightSashForm.layout();
		}
		// Handle other clicks
		else
		{
			while(currentComposites.size() != 0)
			{
				currentComposites.get(0).dispose();
				currentComposites.remove(0);
			}
		}
	}

	private void recurseCheckTreeItem(TreeItem treeItem, boolean checked) {
		TreeObject treeObject = treeObjects.get(treeItem);
		treeItem.setChecked(checked);
		treeObject.setChecked(checked);
		for(TreeItem childItem : treeItem.getItems()) {
			recurseCheckTreeItem(childItem, checked);
		}
	}

	private void updateDisplay(TreeObject to) {
		// Display each DisplayObject
		for(DisplayObject displayObject : to.getDisplayData().getDisplayObjects()) {
			if(displayObject == null || displayObject.getObjects() == null) {
				return;
			}
			// See if the DisplayObject has a list or a single object
			if(displayObject.getObjects().size() == 1) {
				TreeObject treeObject = displayObject.getObjects().get(0);	// There's only 1 item
				
				// Setup the composite we're adding the right side
				Composite labelComposite = new Composite(rightSashForm, SWT.MULTI | SWT.BORDER | SWT.FULL_SELECTION);
				GridLayout gl = new GridLayout(2, false);
				gl.horizontalSpacing = 4;
				gl.verticalSpacing = 4;
				gl.marginBottom = 5;
				gl.marginTop = 5;
				labelComposite.setLayout(gl);
				
				// For each column, create/add a label with the title and the data
				int i = 0;
				for(String columnName : displayObject.getColumnNames()) {
					Label columnNameLabel = new Label(labelComposite, SWT.NONE);
					columnNameLabel.setText(displayObject.getColumnTitles()[i]);
					
					Label columnValueLabel = new Label(labelComposite, SWT.NONE);
					try {
						Field field = treeObject.getClass().getDeclaredField(columnName);
						String val = (String)field.get(treeObject);
						if(val == null)
						{
							val = "";
						}
						columnValueLabel.setText(val);
					} catch (NoSuchFieldException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (IllegalAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					i++;
				}
				
				currentComposites.add(labelComposite);
			}
			else {
				Table table = new Table(rightSashForm, SWT.MULTI | SWT.BORDER | SWT.FULL_SELECTION);
				table.setLinesVisible(true);
				table.setHeaderVisible(true);

				for(String columnName : displayObject.getColumnTitles()) {
					TableColumn column = new TableColumn(table, SWT.NONE);
					column.setText(columnName);
					column.pack();
				}

				for(TreeObject to1 : displayObject.getObjects())
				{
					TableItem item = new TableItem(table, SWT.NONE);
					int i = 0;
					for(String columnName : displayObject.getColumnNames()) {
						try {
							Field field = to1.getClass().getDeclaredField(columnName);
							String val = (String)field.get(to1);
							if(val == null)
							{
								val = "";
							}
							item.setText(i, val);
						} catch (NoSuchFieldException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (IllegalAccessException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						i++;
					}
				}
				// Resize the Columns
				Rectangle area = rightSashForm.getClientArea();
				Point size = table.computeSize(SWT.DEFAULT, SWT.DEFAULT);
				ScrollBar vBar = table.getVerticalBar();
				int width = area.width - table.computeTrim(0,0,0,0).width - vBar.getSize().x;
				if (size.y > area.height + table.getHeaderHeight()) {
					// Subtract the scrollbar width from the total column width
					// if a vertical scrollbar will be required
					Point vBarSize = vBar.getSize();
					width -= vBarSize.x;
				}
				for(TableColumn column : table.getColumns())
				{
					column.setWidth(width / table.getColumnCount());
				}

				// Add to the list of current composites
				currentComposites.add(table);
			}
		}
	}
	
	private void exportPdf() {
		// Save File Dialog
		FileDialog fileDialog = new FileDialog(shell, SWT.SAVE);
		String[] filterNames = new String[] {
			"PDF Files (*.pdf)"
		};
		String[] filterExtensions = new String[] {
			"*.pdf"
		};
		fileDialog.setFilterNames(filterNames);
		fileDialog.setFilterExtensions(filterExtensions);
		fileDialog.setFileName("output");

		// Open the file dialog
		String filename = fileDialog.open();
		
		// Check the filename selected
		if (filename == null) {
			final Shell messageDialog = new Shell(shell, SWT.DIALOG_TRIM);
			messageDialog.setLayout(new GridLayout(1, true));

			Label label = new Label(messageDialog, SWT.NONE);
			label.setText("You did not select a valid filename to save to");

			Button ok = new Button(messageDialog, SWT.PUSH);
			ok.setText("OK");
			ok.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false));
			ok.addSelectionListener(new SelectionAdapter() {
				public void widgetSelected(SelectionEvent e) {
					messageDialog.close();
				}
			});
			messageDialog.setDefaultButton(ok);
			messageDialog.pack();
			messageDialog.open();
			return;
		}
		
		// Generate the report!
		PdfGenerator.generateReport(filename, rootObject);
		//RtfGenerator.generateReport(filename, rootObject);
		System.out.println("Created file: " + filename);
	}
}
