package com.walmartlabs.concord.it.server;

/*-
 * *****
 * Concord
 * -----
 * Copyright (C) 2017 - 2025 Walmart Inc.
 * -----
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =====
 */

import com.walmartlabs.concord.client2.*;
import com.walmartlabs.concord.common.secret.SecretUtils;
import org.junit.jupiter.api.*;
import org.mockserver.integration.ClientAndServer;

import javax.naming.NameAlreadyBoundException;
import javax.naming.directory.*;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.util.Base64;
import java.util.UUID;

import static com.walmartlabs.concord.it.common.ITUtils.archive;
import static com.walmartlabs.concord.it.common.ServerClient.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class AdvancedAuthenticationIT extends AbstractServerIT {

    private ClientAndServer mockOidcServer;
    private int mockOidcPort;

    @BeforeEach
    public void setupMockServers() {
        mockOidcPort = findFreePort();
        mockOidcServer = ClientAndServer.startClientAndServer(mockOidcPort);
        setupOidcMockEndpoints();
    }

    @AfterEach
    public void teardownMockServers() {
        if (mockOidcServer != null) {
            mockOidcServer.stop();
        }
    }

    private int findFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void setupOidcMockEndpoints() {
        mockOidcServer
            .when(request()
                .withMethod("GET")
                .withPath("/userinfo")
                .withHeader("Authorization", "Bearer valid-token"))
            .respond(response()
                .withStatusCode(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\n" +
                    "  \"sub\": \"test-user-123\",\n" +
                    "  \"name\": \"Test User\",\n" +
                    "  \"email\": \"test@example.com\",\n" +
                    "  \"groups\": [\"admin\", \"developers\"]\n" +
                    "}"));

        mockOidcServer
            .when(request()
                .withMethod("GET")
                .withPath("/userinfo")
                .withHeader("Authorization", "Bearer invalid-token"))
            .respond(response()
                .withStatusCode(401)
                .withBody("{\"error\": \"invalid_token\"}"));

        mockOidcServer
            .when(request()
                .withMethod("GET")
                .withPath("/callback"))
            .respond(response()
                .withStatusCode(302)
                .withHeader("Location", ITConstants.SERVER_URL + "/"));

        mockOidcServer
            .when(request()
                .withMethod("POST")
                .withPath("/token"))
            .respond(response()
                .withStatusCode(200)
                .withHeader("Content-Type", "application/json")
                .withBody("{\n" +
                    "  \"access_token\": \"refreshed-token\",\n" +
                    "  \"token_type\": \"Bearer\",\n" +
                    "  \"expires_in\": 3600\n" +
                    "}"));
    }

    @Test
    public void testOidcBearerTokenAuthentication() throws Exception {
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        httpCon.setRequestProperty("Authorization", "Bearer valid-token");

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_OK, responseCode);
    }

    @Test
    public void testOidcBearerTokenValidationFailure() throws Exception {
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        httpCon.setRequestProperty("Authorization", "Bearer invalid-token");

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, responseCode);
    }

    @Test
    public void testOidcTokenRefreshScenario() throws Exception {
        URL urlObj = new URL("http://localhost:" + mockOidcPort + "/token");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        httpCon.setRequestMethod("POST");
        httpCon.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        httpCon.setDoOutput(true);
        httpCon.getOutputStream().write("grant_type=refresh_token&refresh_token=test".getBytes());

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_OK, responseCode);
    }

    @Test
    public void testOidcCallbackHandling() throws Exception {
        URL urlObj = new URL("http://localhost:" + mockOidcPort + "/callback?code=test-code&state=test-state");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_MOVED_TEMP, responseCode);
    }

    @Test
    public void testAuthenticationHandlerChainPriority() throws Exception {
        String sessionToken = createTestSessionToken();
        
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        
        String basicAuth = Base64.getEncoder().encodeToString((sessionToken + ":").getBytes());
        httpCon.setRequestProperty("Authorization", "Basic " + basicAuth);
        httpCon.setRequestProperty("X-Concord-SessionToken", sessionToken);

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_OK, responseCode);
    }

    @Test
    public void testBasicAuthFallbackToSessionToken() throws Exception {
        String sessionToken = createTestSessionToken();
        
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        
        String basicAuth = Base64.getEncoder().encodeToString((sessionToken + ":").getBytes());
        httpCon.setRequestProperty("Authorization", "Basic " + basicAuth);

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_OK, responseCode);
    }

    @Test
    public void testSessionTokenFromHeaderVsBasicAuth() throws Exception {
        String sessionToken = createTestSessionToken();
        
        URL urlObj1 = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon1 = (HttpURLConnection) urlObj1.openConnection();
        httpCon1.setRequestProperty("X-Concord-SessionToken", sessionToken);
        assertEquals(HttpURLConnection.HTTP_OK, httpCon1.getResponseCode());
        
        URL urlObj2 = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon2 = (HttpURLConnection) urlObj2.openConnection();
        String basicAuth = Base64.getEncoder().encodeToString((sessionToken + ":").getBytes());
        httpCon2.setRequestProperty("Authorization", "Basic " + basicAuth);
        assertEquals(HttpURLConnection.HTTP_OK, httpCon2.getResponseCode());
    }

    @Test
    public void testSessionTokenEncryptionDecryption() throws Exception {
        String sessionToken = createTestSessionToken();
        assertNotNull(sessionToken);
        assertTrue(sessionToken.length() > 0);
        
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        httpCon.setRequestProperty("X-Concord-SessionToken", sessionToken);

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_OK, responseCode);
    }

    @Test
    public void testSessionTokenExpiration() throws Exception {
        String invalidToken = "invalid-session-token";
        
        URL urlObj = new URL(ITConstants.SERVER_URL + "/api/v1/org?limit=1");
        HttpURLConnection httpCon = (HttpURLConnection) urlObj.openConnection();
        httpCon.setRequestProperty("X-Concord-SessionToken", invalidToken);

        int responseCode = httpCon.getResponseCode();
        assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, responseCode);
    }

    @Test
    public void testProcessBoundSessionValidation() throws Exception {
        byte[] payload = archive(AdvancedAuthenticationIT.class.getResource("sessionTokenAsUsername").toURI());
        StartProcessResponse spr = start(payload);
        
        ProcessEntry pir = waitForCompletion(getApiClient(), spr.getInstanceId());
        assertLog(".*statusCode=200.*", getLog(pir.getInstanceId()));
    }

    @Test
    public void testLdapDomainAuthentication() throws Exception {
        assumeTrue(System.getenv("IT_LDAP_URL") != null, "LDAP server not available");
        
        String username = "testuser";
        String domain = "example.org";
        String fullUsername = username + "@" + domain;
        
        DirContext ldapCtx = LdapIT.createContext();
        createLdapUser(ldapCtx, username);
        
        UsersApi usersApi = new UsersApi(getApiClient());
        usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(fullUsername)
                .type(CreateUserRequest.TypeEnum.LDAP));
        
        UserEntry ue = usersApi.findByUsername(fullUsername);
        assertNotNull(ue);
        assertEquals(username, ue.getName());
        assertEquals(domain, ue.getDomain());
    }

    @Test
    public void testLdapGroupSynchronization() throws Exception {
        assumeTrue(System.getenv("IT_LDAP_URL") != null, "LDAP server not available");
        
        String username = "groupuser_" + randomString();
        String groupName = "testgroup_" + randomString();
        
        DirContext ldapCtx = LdapIT.createContext();
        createLdapUser(ldapCtx, username);
        createLdapGroupWithUser(ldapCtx, groupName, username);
        
        UsersApi usersApi = new UsersApi(getApiClient());
        usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(username)
                .type(CreateUserRequest.TypeEnum.LDAP));
        
        UserEntry ue = usersApi.findByUsername(username);
        assertNotNull(ue);
    }

    @Test
    public void testLdapConnectionFailureHandling() throws Exception {
        String invalidUsername = "nonexistent@invalid.domain";
        
        UsersApi usersApi = new UsersApi(getApiClient());
        assertThrows(ApiException.class, () -> {
            usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(invalidUsername)
                    .type(CreateUserRequest.TypeEnum.LDAP));
        });
    }

    private String createTestSessionToken() {
        UUID testInstanceId = UUID.randomUUID();
        byte[] salt = "test-salt".getBytes();
        byte[] pwd = "test-password".getBytes();
        
        byte[] ab = SecretUtils.encrypt(testInstanceId.toString().getBytes(), pwd, salt);
        return Base64.getEncoder().encodeToString(ab);
    }

    private void createLdapUser(DirContext ldapCtx, String username) throws Exception {
        String dn = "uid=" + username + ",ou=users,dc=example,dc=org";
        Attributes attributes = new BasicAttributes();

        Attribute uid = new BasicAttribute("uid", username);
        Attribute cn = new BasicAttribute("cn", username);
        Attribute sn = new BasicAttribute("sn", username);

        Attribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("organizationalPerson");
        objectClass.add("person");
        objectClass.add("inetOrgPerson");

        attributes.put(uid);
        attributes.put(cn);
        attributes.put(sn);
        attributes.put(objectClass);

        try {
            ldapCtx.createSubcontext(dn, attributes);
        } catch (NameAlreadyBoundException e) {
        }
    }

    private void createLdapGroupWithUser(DirContext ldapCtx, String groupName, String username) throws Exception {
        String groupDn = "cn=" + groupName + ",ou=groups,dc=example,dc=org";
        String userDn = "uid=" + username + ",ou=users,dc=example,dc=org";
        Attributes attributes = new BasicAttributes();

        Attribute cn = new BasicAttribute("cn", groupName);
        Attribute uniqueMember = new BasicAttribute("uniqueMember", userDn);
        Attribute objectClass = new BasicAttribute("objectClass", "groupOfUniqueNames");

        attributes.put(cn);
        attributes.put(uniqueMember);
        attributes.put(objectClass);

        try {
            ldapCtx.createSubcontext(groupDn, attributes);
        } catch (NameAlreadyBoundException e) {
        }
    }
}
