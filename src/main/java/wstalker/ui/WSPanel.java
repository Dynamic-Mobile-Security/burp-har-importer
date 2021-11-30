/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Jose Selvi, jose dot selvi at nccgroup dot com

https://github.com/nccgroup/BurpImportSitemap

Released under AGPL see LICENSE for more information
*/

package wstalker.ui;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URISyntaxException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.UUID;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Desktop;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;

import wstalker.WStalker;
import wstalker.imports.WSImport;
import wstalker.imports.WSRequestResponse;

public class WSPanel extends JPanel {

    private final burp.IBurpExtenderCallbacks callbacks;
    private final burp.IExtensionHelpers helpers;
    private final WSImport wsimport;
    private final JCheckBox chkFakeParam;
    private final String paramname = "stingrayParamToExclude";

    // Constructor
    public WSPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = this.callbacks.getHelpers();
        this.wsimport = new WSImport();

        // Create the Grid
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[] { 0, 1, 1, 0 };
        gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0 };
        gridBagLayout.columnWeights = new double[] { 0.0, 1.0, 1.0, 0.0, Double.MIN_VALUE };
        gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
        this.setLayout(gridBagLayout);

        // Add NCC Logo Image
        // Borrowed from https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource("AboutPlugin.png");
        JLabel lblMain = new JLabel("NCC LOGO"); // to see the label in eclipse design tab!
        ImageIcon imageIconMain;
        if (imageURLMain != null) {
            imageIconMain = new ImageIcon(imageURLMain);
            lblMain = new JLabel(imageIconMain);
        }
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = gbc.weighty = 0;
        gbc.gridheight = 9;
        gbc.insets = new Insets(15, 15, 15, 15);
        gbc.gridx = 0;
        gbc.gridy = 0;
        this.add(lblMain, gbc);

        gbc.weightx = 1;
        gbc.anchor = GridBagConstraints.NORTHWEST;

        //
        // FAKE PARAMETER TRICK
        //

        JLabel lblFakeParam = new JLabel("Add stingray parameter \"" + this.paramname + "\"");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridheight = 1;
        gbc.gridx = 1;
        gbc.gridy = 0;
        this.add(lblFakeParam, gbc);

        this.chkFakeParam = new JCheckBox("Enable all requests to save");
        this.chkFakeParam.setSelected(true); // do the trick by default
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(chkFakeParam, gbc);

        //
        // NCCGROUP WSTALKER
        //

        JLabel lblImportWStalker = new JLabel("Import CSV Format");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblImportWStalker, gbc);

        JButton btnImportWStalker = new JButton("Import CSV");
        btnImportWStalker.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> rs = wsimport.importWStalker();
                sendToSitemap(rs);
            }
        });
        gbc.insets = new Insets(0, 0, 10, 0);
        gbc.gridwidth = 2;
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(btnImportWStalker, gbc);

        //
        // OWASP ZAP
        //

        // JLabel lblImportZAP = new JLabel("Import OWASP ZAP Format (\"export messages to file\")");
        // gbc.insets = new Insets(20, 0, 5, 5);
        // gbc.gridx = 1;
        // gbc.gridy++;
        // this.add(lblImportZAP, gbc);

        // JButton btnImportZAP = new JButton("Import OWASP ZAP");
        // btnImportZAP.addActionListener(new ActionListener() {
        //     public void actionPerformed(ActionEvent e) {
        //         ArrayList<IHttpRequestResponse> rs = wsimport.importZAP();
        //         sendToSitemap(rs);
        //     }
        // });
        // gbc.insets = new Insets(0, 0, 10, 0);
        // gbc.gridwidth = 2;
        // gbc.gridx = 1;
        // gbc.gridy++;
        // this.add(btnImportZAP, gbc);

        //
        // Load from HAR format
        //

        JLabel lblHarFile = new JLabel("Use HAR file you fools.");
        gbc.insets = new Insets(20, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy++;
        this.add(lblHarFile, gbc);

        JButton btnLoadHarFile = new JButton("load from har file");
        btnLoadHarFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
                boolean doTrick = chkFakeParam.isSelected();
				ArrayList<IHttpRequestResponse> rs = wsimport.loadHAR(doTrick);
                sendToSitemap(rs);
			}
		});
		gbc.insets = new Insets(0, 0, 10, 0);
		gbc.gridwidth = 2;
		gbc.gridx = 1;
		gbc.gridy++;
        this.add(btnLoadHarFile, gbc);
    }

    public void sendToSitemap(ArrayList<IHttpRequestResponse> rs) {    
        boolean doTrick = this.chkFakeParam.isSelected();
        this.sendToSitemap(rs, doTrick);
    }

    public void sendToSitemap(ArrayList<IHttpRequestResponse> rs, boolean doTrick) {    

        Iterator<IHttpRequestResponse> i = rs.iterator();
        while (i.hasNext()) {
            IHttpRequestResponse r = i.next();
            this.sendToSitemap(r, doTrick);
        }
    }

    public void sendToSitemap(IHttpRequestResponse r) {    
        boolean doTrick = this.chkFakeParam.isSelected();
        this.sendToSitemap(r, doTrick);
    }

    public void sendToSitemap(IHttpRequestResponse r, boolean doTrick) {
        WSRequestResponse rr = new WSRequestResponse(r);

        // We add the fake parameter if enabled, to add all requests.
        if (doTrick) {
            final String uuid = UUID.randomUUID().toString();
            IParameter p = this.helpers.buildParameter(this.paramname, uuid, IParameter.PARAM_URL);

            byte[] b = this.helpers.addParameter(rr.getRequest(), p);
            rr.setRequest(b);
        }

        // Add resulting request/response to SiteMap
        this.callbacks.addToSiteMap(rr);
    }
    
    // Requirement
    private static final long serialVersionUID = 5843153017285180474L;
}