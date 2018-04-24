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

package org.keycloak.testsuite.model;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.testsuite.rule.KeycloakRule;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TransactionsTest {

    @ClassRule
    public static KeycloakRule kc = new KeycloakRule();

    @Test
    @Ignore
    public void testTransactionActive() {
        KeycloakSession session = kc.startSession();

        Assert.assertTrue(session.getTransactionManager().isActive());
        session.getTransactionManager().commit();
        Assert.assertFalse(session.getTransactionManager().isActive());

        session.getTransactionManager().begin();
        Assert.assertTrue(session.getTransactionManager().isActive());
        session.getTransactionManager().rollback();
        Assert.assertFalse(session.getTransactionManager().isActive());

        session.close();
    }
}
