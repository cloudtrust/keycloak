package org.keycloak.protocol.saml;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DefaultSamlArtifactResolverFactory implements ArtifactResolverFactory{

    public static final String PROVIDER_ID = "saml-artifact-04-resolver";

    private DefaultSamlArtifactResolver artifactResolver;

    @Override
    public DefaultSamlArtifactResolver create(KeycloakSession session) {
        artifactResolver.initialize(session);
        return artifactResolver;
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to initialize
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        artifactResolver = new DefaultSamlArtifactResolver();
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
