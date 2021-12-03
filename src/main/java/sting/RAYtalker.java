/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Jose Selvi, jose dot selvi at nccgroup dot com

https://github.com/nccgroup/BurpImportSitemap

Released under AGPL see LICENSE for more information
*/

package sting;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;
import javax.swing.JMenuItem;

import burp.ITab;
import sting.ui.RAYPanel;
import burp.IBurpExtender;
import burp.IContextMenuFactory;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class RAYtalker implements ITab, IBurpExtender, IContextMenuFactory {

    public static String Name = "HAR Import Sitemap";
    public static String Url = "https://github.com/swordfish/HarBurpImportSitemap";
    public static IBurpExtenderCallbacks callbacks;
    public static RAYPanel panel;
    public static RAYtalker instance;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        RAYtalker.instance = this;
        RAYtalker.callbacks = callbacks;
        RAYtalker.panel = new sting.ui.RAYPanel(RAYtalker.callbacks);

        callbacks.setExtensionName(RAYtalker.Name);

        // Register Tab
        RAYtalker.callbacks.addSuiteTab(this);

        // Register Context Menus
        RAYtalker.callbacks.registerContextMenuFactory(this);

        // Print "Loaded" message
        PrintWriter stdout = new PrintWriter(RAYtalker.callbacks.getStdout(), true);
        stdout.println("Loaded " + RAYtalker.Name + " Extension");
        stdout.println("");
        stdout.println("░░                                                                      ");
        stdout.println("  ▒▒░░                                                                  ");
        stdout.println("      ▓▓                                                                ");
        stdout.println("        ▒▒▒▒                                            ░░░░            ");
        stdout.println("          ░░▓▓░░                                    ▒▒██                ");
        stdout.println("              ▓▓▓▓░░                              ██▓▓                  ");
        stdout.println("                ░░████░░                      ▒▒██▓▓▒▒                  ");
        stdout.println("                    ▒▒▓▓▓▓░░░░░░            ░░████▓▓                    ");
        stdout.println("                      ░░▓▓▓▓▓▓▓▓▒▒░░  ░░░░▒▒▓▓▓▓▓▓▒▒                    ");
        stdout.println("                ▒▒░░░░  ░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▒▒                  ");
        stdout.println("                    ▒▒██▓▓░░▒▒▓▓██▓▓▒▒████████▓▓▓▓▓▓▒▒▓▓░░              ");
        stdout.println("                      ░░▓▓▒▒▒▒▒▒▓▓▒▒▒▒▒▒██████████▓▓▓▓▒▒▒▒▒▒            ");
        stdout.println("                          ▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓██████▓▓▒▒▒▒▒▒▒▒          ");
        stdout.println("                            ▓▓▓▓▒▒░░░░▒▒▒▒▒▒▒▒▓▓██████▓▓▓▓▒▒▒▒▒▒        ");
        stdout.println("                            ░░▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓▓████████▓▓▓▓▒▒▒▒░░      ");
        stdout.println("                              ▒▒▓▓▓▓▓▓▓▓▒▒▒▒░░▒▒▒▒▓▓██████▓▓▓▓▒▒▓▓      ");
        stdout.println("                                ▒▒▓▓▓▓▓▓▒▒▓▓▒▒▒▒▒▒▒▒▓▓████████▓▓▒▒░░    ");
        stdout.println("                                ████▓▓▒▒████▓▓▒▒░░▒▒▒▒▒▒▓▓████▓▓▓▓▓▓    ");
        stdout.println("                              ▒▒▓▓    ▒▒▓▓██▓▓▓▓▓▓▒▒▒▒▒▒▓▓▓▓████▓▓▓▓▒▒  ");
        stdout.println("                              ▓▓        ▒▒██▓▓▒▒▒▒▓▓▓▓▓▓▒▒▓▓▓▓████▓▓▓▓  ");
        stdout.println("                                          ██▓▓▒▒▓▓░░░░▒▒▓▓▒▒▓▓▓▓████▓▓▒▒");
        stdout.println("                                          ▓▓▓▓    ▓▓▒▒░░▒▒▒▒▒▒▓▓████▓▓▓▓");
        stdout.println("                                            ▓▓      ░░▓▓░░▒▒▒▒▒▒▓▓████▓▓");
        stdout.println("                                            ▓▓          ▓▓▒▒▒▒▓▓▒▒████▓▓");
        stdout.println("                                              ▒▒          ▒▒░░▓▓▒▒████▓▓");
        stdout.println("                                                            ▓▓▒▒▓▓▓▓██▓▓");
        stdout.println("                                                            ▒▒▒▒▓▓▓▓██▓▓");
        stdout.println("                                                            ░░░░▓▓▓▓██▒▒");
        stdout.println("                                              ░░            ░░▒▒▓▓▓▓▓▓  ");
        stdout.println("                                              ▒▒            ▒▒▒▒▓▓██▓▓  ");
        stdout.println("                                              ▒▒            ▓▓▒▒▓▓▓▓    ");
        stdout.println("                                            ▒▒▒▒        ░░▓▓██▓▓██      ");
        stdout.println("                                            ▓▓▓▓    ▓▓▓▓▓▓▓▓▒▒██        ");
        stdout.println("                                            ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓            ");
        stdout.println("                                          ▓▓▓▓▒▒  ▓▓  ▓▓▓▓              ");
        stdout.println("                                          ▓▓▓▓        ▓▓                ");
        stdout.println("                                          ▓▓        ▒▒▒▒                ");
        stdout.println("                                        ▓▓▒▒                            ");
        stdout.println("                                      ░░▓▓                              ");
        stdout.println("                                                                        ");
        stdout.println("                                                                        ");
        stdout.println("                                                                        ");
        stdout.println("                                                                        ");
        stdout.println("                                                                        ");
        stdout.println("      ░░░░  ░░░░░░░░  ░░5w02df15h░░░░53cu217y░░░░░░░░  ░░░░  ░░░░       ");
    }

    @Override
    public String getTabCaption() {
        return RAYtalker.Name;
    }

    @Override
    public Component getUiComponent() {
        return RAYtalker.panel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new LinkedList<JMenuItem>();
        IHttpRequestResponse a[] = invocation.getSelectedMessages();
        
        // Exit if no request/response selected
        if ( a.length == 0 ) {
            return items;
        }

        // Convert Array into ArrayList
        ArrayList<IHttpRequestResponse> rs = new ArrayList<IHttpRequestResponse>();
        for(IHttpRequestResponse x:a) {
            rs.add(x);
        }
        
        // Create Default Menu (using fake parameter)
        JMenuItem itemDefault = new JMenuItem("Send To Sitemap");
        itemDefault.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                panel.sendToSitemap(rs, true);
            }
        });
        items.add(itemDefault);

        // Create Alternative Menu (NOT using fake parameter)
        JMenuItem itemNoFakeParam = new JMenuItem("Send To Sitemap (no fakeparam)");
        itemNoFakeParam.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                panel.sendToSitemap(rs, false);
            }
        });
        items.add(itemNoFakeParam);

        return items;
    }
}