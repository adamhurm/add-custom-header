package burp;

import java.awt.Component;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.JPanel;

import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, IHttpListener, ITab {

    IExtensionHelpers helpers = null;
    Pattern p;

    static String extensionName = "CSRF Token Maintainer";
    IBurpExtenderCallbacks callbacks = null;

    // some default values
    final String DEFAULT_HEADER_NAME = "CSRF-Token";
    final String DEFAULT_HEADER_VALUE_PREFIX = "";
    final String DEFAULT_REGEXP = "CSRF-Token: (([a-z0-9]{4,12}-?){10})";
    final String DEFAULT_HARDCODED_VALUE = "<insert static JWT token here>";

    String existingToken = null;
    public static final List<Integer> SYNC_TARGET_TOOL_LIST = Arrays.asList( IBurpExtenderCallbacks.TOOL_REPEATER,
			IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_INTRUDER,
			IBurpExtenderCallbacks.TOOL_SEQUENCER, IBurpExtenderCallbacks.TOOL_SPIDER );
    
    private BurpTab tab;

    void useRegExp() {

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        this.helpers = callbacks.getHelpers();
        callbacks.registerSessionHandlingAction(this);
	    // ADAM: register HTTP Listener to update token for subsequent requests.
	    callbacks.registerHttpListener(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                tab = new BurpTab();

                // set some default values
                tab.setHeaderName(DEFAULT_HEADER_NAME);
                tab.setHeaderValuePrefix(DEFAULT_HEADER_VALUE_PREFIX);
                tab.setRegExpText(DEFAULT_REGEXP);
                tab.setHardCodedText(DEFAULT_HARDCODED_VALUE);
                // force update the example label
                tab.updateFinalResultLabel();
                // customize our UI components
                callbacks.customizeUiComponent(tab);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        callbacks.printOutput("CSRF Token Maintainer loaded. -- Based on \"Add Custom Header\". Modified by ahurm.");
    }

    
    // methods below from ISessionHandlingAction
    @Override
    public String getActionName() {
        return extensionName;
    }

    
    public void performAction(IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems) {

        String token = null;

        if (tab.useHardCoded()) {
            // token has priority over regexp
            token = tab.getHardCodedText();
        } else if (tab.useRegExp()) {
            if (macroItems.length == 0) {
                this.callbacks.issueAlert("No macro configured or macro did not return any response");
                return;
            }
            String regexp = tab.getRegExpText();
            try {
                p = Pattern.compile(regexp);
            } catch (PatternSyntaxException e) {
                this.callbacks.issueAlert("Syntax error in regular expression (see extension error window)");
                callbacks.printError(e.toString());
                return;
            }

            // go through all macros and run the regular expression on their body
            for (int i = 0; i < macroItems.length; i++) {
                byte[] _response = macroItems[i].getResponse();
                if (_response == null) return;
                IResponseInfo macroResponse = helpers.analyzeResponse(_response);
                if (macroResponse == null) return;
                //ADAM: made changes below to get full response instead of responseBody
		        //int bodyOffset = macroResponse.getBodyOffset();
                String response = helpers.bytesToString(_response); //.substring(bodyOffset)
                Matcher m = p.matcher(response);
                if (m.find()) {
                    token = m.group(1);
                    if (token != null && token.length() > 0) {
                        // found it
                        //ADAM: store token for future use
			            existingToken = token;
			            break;
                    }
                }
            }
        } else {
            // using the 'disable' button
            return;
        }

        if (token == null) {
            // nothing found: failing silently to avoid polluting the logs
            callbacks.printError("No token found");
            return;
        }

        String headerName = tab.getHeaderName();
        String headerValuePrefix = tab.getHeaderValuePrefix();
        
        IRequestInfo rqInfo = helpers.analyzeRequest(currentRequest);
        // retrieve all headers
        ArrayList<String> headers = (ArrayList<String>) rqInfo.getHeaders();
        for (int i = 0; i < headers.size(); i++) {
            if (((String) headers.get(i)).startsWith(headerName + ": " + headerValuePrefix)) {
                // there could be more than one header like this; remove and continue
                headers.remove(i);
            }
        }
        String newHeader = headerName + ": " + headerValuePrefix + token;
        headers.add(newHeader);
        callbacks.printOutput("Added header: '" + newHeader + "'");

        String request = new String(currentRequest.getRequest());
        String messageBody = request.substring(rqInfo.getBodyOffset());
        // rebuild message
        byte[] message = helpers.buildHttpMessage(headers, messageBody.getBytes());
        currentRequest.setRequest(message);
    }
    // end ISessionHandlingAction methods

    //method from IHttpListener
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //ADAM: skip token replacement if existingToken has not been set yet
        if (existingToken == null) return;
        String token = null;
	
        try {
            if(SYNC_TARGET_TOOL_LIST.contains(toolFlag)){
            // the below is grabbed from the performAction method
            if (tab.useHardCoded()) {
                // token has priority over regexp
                token = tab.getHardCodedText();
            } else if (tab.useRegExp()) {
                String regexp = tab.getRegExpText();
                try {
                    p = Pattern.compile(regexp);
                } catch (PatternSyntaxException e) {
                    this.callbacks.issueAlert("Syntax error in regular expression (see extension error window)");
                    callbacks.printError(e.toString());
                    return;
                }

                // process when message is request.
                if (messageIsRequest) {
                byte[] rawRequest = messageInfo.getRequest();
                if (rawRequest == null) return;
                IRequestInfo _request = helpers.analyzeRequest(rawRequest);
                if (_request == null) return;
                String request = helpers.bytesToString(rawRequest);
                Matcher m = p.matcher(request);
                    if (m.find()) {
                        token = m.group(1);
                        if (token != null && token.length() > 0) {
                            if (token.equals(existingToken)) return;
                            else token = existingToken;
                        }
                    }
                }
            } else {
                // using the 'disable' button
                return;
            }  

            if (token == null) {
                // nothing found: failing silently to avoid performance impact since this is run every request
                return;
            }

            String headerName = tab.getHeaderName();
            String headerValuePrefix = tab.getHeaderValuePrefix();

            IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
            
            // retrieve all headers
            ArrayList<String> headers = (ArrayList<String>) rqInfo.getHeaders();
            for (int i = 0; i < headers.size(); i++) {
                if (((String) headers.get(i)).startsWith(headerName + ": " + headerValuePrefix)) {
                    // there could be more than one header like this; remove and continue
                    headers.remove(i);
                }
            }
            String newHeader = headerName + ": " + headerValuePrefix + token;
            headers.add(newHeader);
            callbacks.printOutput("Added header: '" + newHeader + "'");

            String request = new String(messageInfo.getRequest());
            String messageBody = request.substring(rqInfo.getBodyOffset());

            // rebuild message
            byte[] message = helpers.buildHttpMessage(headers, messageBody.getBytes());
            messageInfo.setRequest(message);
            }
        } catch (Exception e) {
            callbacks.printError("An error occurred while attempting to modify this HTTP message: "+e);
        }
	}

    // ITab methods
    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }
    // end ITab methods

}
