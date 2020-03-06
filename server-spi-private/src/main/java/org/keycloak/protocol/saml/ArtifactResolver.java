package org.keycloak.protocol.saml;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.Provider;
import org.w3c.dom.Document;

import java.util.List;


/**
 * Provides a way to create artifacts and resolve them
 */
public interface ArtifactResolver extends Provider {

    ClientModel selectSourceClient(String artifact, List<ClientModel> clients) throws ArtifactResolverProcessingException;

    String buildAuthnArtifact(String entityId, Document samlDocument, AuthenticatedClientSessionModel clientSession) throws ArtifactResolverProcessingException, ArtifactResolverConfigException;

    String buildLogoutArtifact(String entityId, Document samlDocument, UserSessionModel userSession) throws ArtifactResolverProcessingException, ArtifactResolverConfigException;

    String resolveArtifact(String artifact) throws ArtifactResolverProcessingException;

    void initialize(KeycloakSession session);

}
