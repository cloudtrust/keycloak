package org.keycloak.testsuite.util.saml;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.dom.saml.v2.protocol.StatusResponseType;
import org.keycloak.protocol.saml.profile.util.Soap;
import org.keycloak.saml.SAML2LogoutResponseBuilder;
import org.keycloak.saml.processing.api.saml.v2.response.SAML2Response;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.w3c.dom.Document;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;

public class SamlBackchannelLogoutReceiver implements AutoCloseable {

    private final HttpServer server;
    private LogoutRequestType logoutRequest;
    private final String url;
    private final String clientEntityId;

    public SamlBackchannelLogoutReceiver(int port, String clientEntityId) {
        this.clientEntityId = clientEntityId;
        try {
            InetSocketAddress address = new InetSocketAddress(InetAddress.getByName("localhost"), port);
            server = HttpServer.create(address, 0);
            this.url = "http://" + address.getHostString() + ":" + port;
        } catch (IOException e) {
            throw new RuntimeException("Cannot create http server", e);
        }

        server.createContext("/", new SamlBackchannelLogoutReceiver.SamlBackchannelLogoutHandler());
        server.setExecutor(null);
        server.start();
    }

    public String getUrl() {
        return url;
    }

    public boolean isLogoutRequestReceived() {
        return logoutRequest != null;
    }

    public LogoutRequestType getLogoutRequest() {
        return logoutRequest;
    }

    @Override
    public void close() throws Exception {
        server.stop(0);
    }

    private class SamlBackchannelLogoutHandler implements HttpHandler {
        public void handle(HttpExchange t) throws IOException {
            try {
                t.getResponseHeaders().add(HttpHeaders.CONTENT_TYPE, "text/xml");
                t.sendResponseHeaders(500, 0);

                Document request = Soap.extractSoapMessage(t.getRequestBody());
                SAMLDocumentHolder samlDoc = SAML2Response.getSAML2ObjectFromDocument(request);
                if (!(samlDoc.getSamlObject() instanceof LogoutRequestType)) {
                    throw new RuntimeException("Message received from ArtifactResolveService is not an ArtifactResponseMessage");
                }
                logoutRequest = (LogoutRequestType) samlDoc.getSamlObject();
                StatusResponseType logoutResponse = new SAML2LogoutResponseBuilder()
                        .issuer(clientEntityId)
                        .logoutRequestID(logoutRequest.getID())

                        .buildModel();
                Document doc = SAML2Response.convert(logoutResponse);

                // send logout response
                OutputStream os = t.getResponseBody();
                os.write(Soap.createMessage().addToBody(doc).getBytes());
                os.close();
            } catch (Exception ex) {
                t.sendResponseHeaders(500, 0);
            }
        }
    }
}


