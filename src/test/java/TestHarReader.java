/*
https://github.com/sdstoehr/har-reader

This format need to be:
METHOD + URL + HEADERS + BODY
GET /api/users HTTP/1.1\r\nHost: reqres.in\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0\r\nAccept: * /*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nContent-Type: application/json\r\nDNT: 1\r\nConnection: keep-alive\r\nReferer: https://reqres.in/\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Site: same-origin\r\nIf-None-Match: W/"406-ut0vzoCuidvyMf8arZpMpJ6ZRDw"\r\n\r\n\r\n

*/

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderMode;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.Har;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarRequest;
import de.sstoehr.harreader.model.HarResponse;
import de.sstoehr.harreader.model.HarHeader;


import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;


public class TestHarReader {
    static private String hostName = "";

    public static void main(String[] args) {
        System.out.println("Test functionality of the Harreader.\n");
        checkTheSound();
    }

    public static void checkTheSound() {
        String delimeter = "\\r\\n";

        // check the current directory
        System.out.println("Working Directory = " + System.getProperty("user.dir"));
        //String filename = "src/test/resoureces/mock_api.har";
        String filename = "../sting_networking/data.har";

        HarReader harReader = new HarReader();
        Har har = null;
        try {
            //har = harReader.readFromFile(new File(filename), HarReaderMode.LAX);
            har = harReader.readFromFile(new File(filename));
        } catch (HarReaderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // System.out.println();
        //System.out.println( har.getLog().getEntries().get(0).getServerIPAddress() );
        //System.out.println(har.getLog().getEntries().get(0).getRequest().getUrl());

        Iterator<HarEntry> items = har.getLog().getEntries().iterator() ;

        // TODO
        while (items.hasNext()) {
            try {
                // TODO - HAR logic parsing
                // format: METHOD + URL(PATH) + Version + HEADERS + BODY
                HarEntry reqRespEntry = items.next();
                System.out.println("\n The HarEntry: " + reqRespEntry);
                //String[] v = line.split(","); // Format: "base64(request),base64(response),url"
                HarRequest harRequest = reqRespEntry.getRequest();
                HarResponse harResponse = reqRespEntry.getResponse();

                System.out.println("request: ");
                System.out.println(harRequest.getMethod().name() );
                System.out.println(harRequest.getHttpVersion() );
                System.out.println( printHeaders(harRequest.getHeaders()) );
                //System.out.println(harRequest.getHeaders().toString() );
                System.out.println(harRequest.getUrl());
                System.out.println("\nPath of url is: " + getPath(harRequest.getUrl()));
                
                System.out.println(harRequest.getPostData().getText() );
                System.out.println("POST DATA is empty?: " + harRequest.getPostData().getText() + " - " + harRequest.getPostData().getText().length());
                //System.out.println(harRequest.toString() );

                System.out.println("The Response: ");
                System.out.println(harResponse.toString());
                System.out.println(harResponse.getStatus());
                System.out.println(harResponse.getStatusText());
                System.out.println(harResponse.getHttpVersion());

                // TODO - привести к похожему формату как в CSV...
                //byte[] request = helpers.stringToBytes(harRequest.toString());
                //byte[] response = helpers.stringToBytes(harResponse.toString());

                System.out.println(harRequest.getUrl());
                //String url = harRequest.getUrl();
                //WSRequestResponse x = new WSRequestResponse(url, request, response);
                //requests.add(x);

            } catch (Exception e) {
                //return new ArrayList<IHttpRequestResponse>();
            }
        }
    }

    static public String printHeaders(List<HarHeader> headers) {
        StringBuilder headersString = new StringBuilder();
        String delimeter = "\\r\\n";

        Iterator<HarHeader> items = headers.iterator();
        while (items.hasNext()) {
            HarHeader header = items.next();
            getHost(header);
            System.out.println(header.toString() );
            System.out.println(header.getName() );
            System.out.println(header.getValue() );
            headersString.append(header.getName()).append(": ").append(header.getValue()).append(delimeter);
        }
        //System.out.println("StringBuilder is: " + headersString);
        //System.out.println(headersString.toString() );

        return headersString.toString();
    }

    static public String getHost(HarHeader header) {
        //String hostName = "";
        if ( "Host".equals(header.getName()) )
            hostName = header.getValue();
        return hostName;
    }

    static public String getPath(String url) {
        String pathUrl = url.substring(url.indexOf(hostName) + hostName.length(), url.length());
        //System.out.println( "Host name is = " + hostName);
        //String pathUrl = harRequest.getUrl().substring(harRequest.getUrl().indexOf(hostName) + hostName.length(), harRequest.getUrl().length() );
        //System.out.println( "Last index = " + harRequest.getUrl().lastIndexOf(hostName)); 
        //System.out.println( pathUrl );               // PATH-should be
        // text.substring(text.indexOf('(') + 1, text.indexOf(')')));
        // text.substring(text.lastIndexOf('-') + 1, text.indexOf('.')));
        System.out.println("inner Path url: " + pathUrl );

        return pathUrl;
    }
}