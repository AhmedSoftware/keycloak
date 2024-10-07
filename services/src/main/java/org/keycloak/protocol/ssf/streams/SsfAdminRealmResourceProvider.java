package org.keycloak.protocol.ssf.streams;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

public class SsfAdminRealmResourceProvider implements AdminRealmResourceProvider {

    private final KeycloakSession session;

    public SsfAdminRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new StreamManagementResource(session, realm, auth, adminEvent);
    }

    @Override
    public void close() {

    }
}
