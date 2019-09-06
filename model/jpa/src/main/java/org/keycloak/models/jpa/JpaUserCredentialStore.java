/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.models.jpa;

import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.CredentialEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JpaUserCredentialStore implements UserCredentialStore {

    private final KeycloakSession session;
    protected final EntityManager em;

    public JpaUserCredentialStore(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    @Override
    public void updateCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        CredentialEntity entity = em.find(CredentialEntity.class, cred.getId());
        if (entity == null) return;
        entity.setCreatedDate(cred.getCreatedDate());
        entity.setUserLabel(cred.getUserLabel());
        entity.setType(cred.getType());
        entity.setSecretData(cred.getSecretData());
        entity.setCredentialData(cred.getCredentialData());
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel cred) {
        CredentialEntity entity = createCredentialEntity(realm, user, cred);
        return toModel(entity);
    }

    @Override
    public boolean removeStoredCredential(RealmModel realm, UserModel user, String id) {
        CredentialEntity entity = removeCredentialEntity(id);
        return entity != null;
    }

    @Override
    public CredentialModel getStoredCredentialById(RealmModel realm, UserModel user, String id) {
        CredentialEntity entity = em.find(CredentialEntity.class, id);
        if (entity == null) return null;
        return toModel(entity);
    }

    CredentialModel toModel(CredentialEntity entity) {
        CredentialModel model = new CredentialModel();
        model.setId(entity.getId());
        model.setType(entity.getType());
        model.setUserLabel(entity.getUserLabel());
        model.setSecretData(entity.getSecretData());
        model.setCredentialData(entity.getCredentialData());
        return model;
    }

    @Override
    public List<CredentialModel> getStoredCredentials(RealmModel realm, UserModel user) {
        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
        TypedQuery<CredentialEntity> query = em.createNamedQuery("credentialByUser", CredentialEntity.class)
                .setParameter("user", userEntity);
        List<CredentialEntity> results = query.getResultList();
        //order the list correctly
        Map<String, CredentialEntity> credentialMap = new HashMap<>();
        CredentialEntity current = null;
        for (CredentialEntity ce : results) {
            credentialMap.put(ce.getId(), ce);
            if (ce.getPreviousCredentialLink() == null) {
                current = ce;
            }
        }
        List<CredentialModel> rtn = new LinkedList<>();
        if (current != null) {
            while (current.getNextCredentialLink() != null) {
                rtn.add(toModel(current));
                current = credentialMap.get(current.getNextCredentialLink());
            }
            rtn.add(toModel(current));
        }
        return rtn;
    }

    @Override
    public List<CredentialModel> getStoredCredentialsByType(RealmModel realm, UserModel user, String type) {
        return getStoredCredentials(realm, user).stream().filter(credential -> type.equals(credential.getType())).collect(Collectors.toList());
    }

    @Override
    public CredentialModel getStoredCredentialByNameAndType(RealmModel realm, UserModel user, String name, String type) {
        List<CredentialModel> results = getStoredCredentials(realm, user).stream().filter(credential ->
                type.equals(credential.getType()) && name.equals(credential.getUserLabel())).collect(Collectors.toList());
        if (results.isEmpty()) return null;
        return results.get(0);
    }

    @Override
    public void close() {

    }

    CredentialEntity createCredentialEntity(RealmModel realm, UserModel user, CredentialModel cred) {
        CredentialEntity entity = new CredentialEntity();
        String id = cred.getId() == null ? KeycloakModelUtils.generateId() : cred.getId();
        entity.setId(id);
        entity.setCreatedDate(cred.getCreatedDate());
        entity.setUserLabel(cred.getUserLabel());
        entity.setType(cred.getType());
        entity.setSecretData(cred.getSecretData());
        entity.setCredentialData(cred.getCredentialData());
        UserEntity userRef = em.getReference(UserEntity.class, user.getId());
        entity.setUser(userRef);

        //add in linkedlist
        CredentialEntity lastCredential = findLastCredentialInList(user);
        if (lastCredential != null) {
            putCredentialInLinkedListAfterCredential(entity, lastCredential.getId());
        }

        em.persist(entity);
        return entity;
    }

    CredentialEntity removeCredentialEntity(String id) {
        CredentialEntity entity = em.find(CredentialEntity.class, id);
        if (entity == null) return null;
        takeOutCredentialAndRepairList(entity);
        em.remove(entity);
        return entity;
    }

    ////Operations to handle the linked list of credentials
    @Override
    public void moveCredentialTo(RealmModel realm, UserModel user, String id, String newPreviousCredentialId) {
        if (newPreviousCredentialId == null) {
            setCredentialAsFirst(realm, user, id);
        }
        CredentialEntity credentialToMove = em.find(CredentialEntity.class, id);
        //moved to the same place, do nothing
        if (newPreviousCredentialId == credentialToMove.getPreviousCredentialLink() || id == newPreviousCredentialId){
            return;
        }
        takeOutCredentialAndRepairList(credentialToMove);
        putCredentialInLinkedListAfterCredential(credentialToMove, newPreviousCredentialId);
    }

    public void setCredentialAsFirst(RealmModel realm, UserModel user, String id)  {
        CredentialEntity credentialToMove = em.find(CredentialEntity.class, id);
        //moved to the same place, do nothing
        if (credentialToMove.getPreviousCredentialLink() == null) {
            return;
        }
        takeOutCredentialAndRepairList(credentialToMove);
        CredentialEntity currentFirst = findFirstCredentialInList(user);
        credentialToMove.setPreviousCredentialLink(null);
        credentialToMove.setNextCredentialLink(currentFirst.getId());
        currentFirst.setPreviousCredentialLink(credentialToMove.getId());
    }

    /**
     * Takes out a credentialEntity from the linkedList and repairs the list by attaching the previous and next together
     * @param ce The CredentialEntity to remove
     */
    private void takeOutCredentialAndRepairList(CredentialEntity ce) {
        //
        if (ce.getPreviousCredentialLink() != null) {
            CredentialEntity currentPreviousCredential = em.find(CredentialEntity.class,ce.getPreviousCredentialLink());
            currentPreviousCredential.setNextCredentialLink(ce.getNextCredentialLink());
        }
        if (ce.getNextCredentialLink() != null) {
            CredentialEntity currentNextCredential = em.find(CredentialEntity.class,ce.getNextCredentialLink());
            currentNextCredential.setPreviousCredentialLink(ce.getPreviousCredentialLink());
        }
    }

    private void putCredentialInLinkedListAfterCredential(CredentialEntity ce, String newPreviousCredentialId) {
        CredentialEntity newPreviousCredential = em.find(CredentialEntity.class, newPreviousCredentialId);
        ce.setPreviousCredentialLink(newPreviousCredentialId);
        ce.setNextCredentialLink(newPreviousCredential.getNextCredentialLink());
        if (newPreviousCredential.getNextCredentialLink() != null) {
            CredentialEntity currentNextCredential = em.find(CredentialEntity.class,newPreviousCredential.getNextCredentialLink());
            currentNextCredential.setPreviousCredentialLink(ce.getId());
        }
        newPreviousCredential.setNextCredentialLink(ce.getId());
    }

    private CredentialEntity findFirstCredentialInList(UserModel user){
        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
        TypedQuery<CredentialEntity> query = em.createNamedQuery("firstCredentialInList", CredentialEntity.class)
                .setParameter("user", userEntity);
        List<CredentialEntity> results = query.getResultList();
        return (results.isEmpty())?null:results.get(0);
    }

    private CredentialEntity findLastCredentialInList(UserModel user) {
        UserEntity userEntity = em.getReference(UserEntity.class, user.getId());
        TypedQuery<CredentialEntity> query = em.createNamedQuery("lastCredentialInList", CredentialEntity.class)
                .setParameter("user", userEntity);
        List<CredentialEntity> results = query.getResultList();
        return (results.isEmpty())?null:results.get(0);
    }


}
