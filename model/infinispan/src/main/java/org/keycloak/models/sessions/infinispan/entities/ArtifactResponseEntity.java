package org.keycloak.models.sessions.infinispan.entities;

import org.infinispan.commons.marshall.Externalizer;
import org.infinispan.commons.marshall.MarshallUtil;
import org.infinispan.commons.marshall.SerializeWith;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Objects;


@SerializeWith(ArtifactResponseEntity.ExternalizerImpl.class)
public class ArtifactResponseEntity extends SessionEntity {

    public static final Logger logger = Logger.getLogger(ArtifactResponseEntity.class);

    private String artifactResponse;

    public ArtifactResponseEntity(){
    }

    public ArtifactResponseEntity(String realmId, String artifactResponse){
        super(realmId);
        this.artifactResponse = artifactResponse;
    }

    public String getArtifactResponse() {
        return artifactResponse;
    }

    public void setArtifactResponse(String artifactResponse) {
        this.artifactResponse = artifactResponse;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (!(o instanceof ArtifactResponseEntity)) {
            return false;
        }

        ArtifactResponseEntity that = (ArtifactResponseEntity) o;

        return Objects.equals(artifactResponse, that.artifactResponse);
    }

    @Override
    public int hashCode() {
        return Objects.hash(artifactResponse);
    }

    @Override
    public String toString() {
        return String.format("ArtifactResponseEntity [ realm=%s, artifactResponse=%s ]", getRealmId(), artifactResponse);
    }


    public static class ExternalizerImpl implements Externalizer<ArtifactResponseEntity> {

        private static final int VERSION_1 = 1;

        @Override
        public void writeObject(ObjectOutput output, ArtifactResponseEntity value) throws IOException {
            output.writeByte(VERSION_1);

            MarshallUtil.marshallString(value.getRealmId(), output);
            MarshallUtil.marshallString(value.artifactResponse, output);
        }

        @Override
        public ArtifactResponseEntity readObject(ObjectInput input) throws IOException {
            switch (input.readByte()) {
                case VERSION_1:
                    return readObjectVersion1(input);
                default:
                    throw new IOException("Unknown version");
            }
        }

        public ArtifactResponseEntity readObjectVersion1(ObjectInput input) throws IOException {
            return new ArtifactResponseEntity(
                    MarshallUtil.unmarshallString(input),
                    MarshallUtil.unmarshallString(input));
        }
    }

}