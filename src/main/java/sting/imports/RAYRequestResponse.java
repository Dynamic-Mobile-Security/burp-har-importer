/*
Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Jose Selvi, jose dot selvi at nccgroup dot com

https://github.com/nccgroup/BurpImportSitemap

Released under AGPL see LICENSE for more information
*/

package sting.imports;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;

class RAYHttpService implements IHttpService {

    private String host;
    private int port;
    private String protocol;

    RAYHttpService(String urlS) {
        URL url;
        try {
            url = new URL(urlS);
        } catch (Exception e) {
            return;
        }

        host = url.getHost();
        protocol = url.getProtocol();
        port = url.getPort();

        if ( port < 1 ) {
            switch (protocol) {
                case "http":
                    port = 80;
                    break;
                case "https":
                    port = 443;
                    break;
            }
        }
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return protocol;
    }

}

public class RAYRequestResponse implements IHttpRequestResponse {

    private IHttpService service;
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;


    public RAYRequestResponse(String url, byte[] req, byte[] res) {
        RAYHttpService srv = new RAYHttpService(url);
        setHttpService(srv);
        setRequest(req);
        setResponse(res);
    }

    public RAYRequestResponse(IHttpRequestResponse r) {
        setComment(r.getComment());
        setHighlight(r.getHighlight());
        setHttpService(r.getHttpService());
        setRequest(r.getRequest());
        setResponse(r.getResponse());
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String c) {
        comment = c;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        highlight = color;

    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        service = httpService;
    }

}