package com.walmartlabs.concord.it.server;

/*-
 * *****
 * Concord
 * -----
 * Copyright (C) 2017 - 2018 Walmart Inc.
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
import org.junit.jupiter.api.Test;

import javax.naming.Context;
import javax.naming.NameAlreadyBoundException;
import javax.naming.directory.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class UserManagementIT extends AbstractServerIT {

    @Test
    public void test() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());

        String username = "user_" + randomString();

        CreateUserResponse cur = usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(username)
                .type(CreateUserRequest.TypeEnum.LOCAL));
        assertTrue(cur.getOk());

        // ---

        ApiKeysApi apiKeyResource = new ApiKeysApi(getApiClient());
        CreateApiKeyResponse cakr = apiKeyResource.createUserApiKey(new CreateApiKeyRequest().username(username));
        assertTrue(cakr.getOk());

        // ---

        usersApi.deleteUser(cur.getId());
    }

    @Test
    public void testAdmins() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());

        String userAName = "userA_" + randomString();
        usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(userAName)
                .type(CreateUserRequest.TypeEnum.LOCAL));

        // ---

        ApiKeysApi apiKeyResource = new ApiKeysApi(getApiClient());
        CreateApiKeyResponse apiKey = apiKeyResource.createUserApiKey(new CreateApiKeyRequest().username(userAName));

        // ---

        setApiKey(apiKey.getKey());

        String userBName = "userB_" + randomString();
        try {
            usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(userBName)
                    .type(CreateUserRequest.TypeEnum.LOCAL));
            fail("should fail");
        } catch (ApiException e) {
        }

        // ---

        resetApiKey();
        usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(userAName)
                .type(CreateUserRequest.TypeEnum.LOCAL));

        usersApi.updateUserRoles(userAName, new UpdateUserRolesRequest()
                .roles(Collections.singleton("concordAdmin")));

        // ---

        setApiKey(apiKey.getKey());
        usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(userBName)
                .type(CreateUserRequest.TypeEnum.LOCAL));
    }

    @Test
    public void testWithRoles() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());

        String roleName = "role_" + randomString();
        String username = "user_" + randomString();

        RolesApi rolesApi = new RolesApi(getApiClient());
        RoleOperationResponse ror = rolesApi.createOrUpdateRole(new RoleEntry().name(roleName));
        assertEquals(RoleOperationResponse.ResultEnum.CREATED, ror.getResult());

        CreateUserResponse cur = usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(username)
                .type(CreateUserRequest.TypeEnum.LOCAL)
                .roles(Collections.singleton(roleName)));
        assertTrue(cur.getOk());

        UserEntry userEntry = usersApi.findByUsername(username);
        assertNotNull(userEntry);
        assertEquals(roleName, userEntry.getRoles().iterator().next().getName());

        // ---

        DeleteUserResponse dur = usersApi.deleteUser(cur.getId());
        assertTrue(dur.getOk());

        GenericOperationResult delete = rolesApi.deleteRole(roleName);
        assertEquals(GenericOperationResult.ResultEnum.DELETED, delete.getResult());
    }

    @Test
    public void testSpecialCharactersInUsernames() throws Exception {
        String userName = "usEr_" + randomString() + "@domain.local";

        UsersApi usersApi = new UsersApi(getApiClient());
        CreateUserResponse cur = usersApi.createOrUpdateUser(new CreateUserRequest()
                .username(userName)
                .type(CreateUserRequest.TypeEnum.LOCAL));
        assertNotNull(cur.getId());

        UserEntry e = usersApi.findByUsername(userName);
        assertEquals(userName.toLowerCase(), e.getName());
    }

    @Test
    public void testUserCreationWithVariousPermissionLevels() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());
        RolesApi rolesApi = new RolesApi(getApiClient());
        ApiKeysApi apiKeysApi = new ApiKeysApi(getApiClient());

        String basicRoleName = "basicRole_" + randomString();
        String adminRoleName = "adminRole_" + randomString();
        String basicUserName = "basicUser_" + randomString();
        String adminUserName = "adminUser_" + randomString();

        try {
            Set<String> basicPermissions = new HashSet<>();
            basicPermissions.add("createProject");

            Set<String> adminPermissions = new HashSet<>();
            adminPermissions.add("createOrg");
            adminPermissions.add("updateOrg");

            rolesApi.createOrUpdateRole(new RoleEntry()
                    .name(basicRoleName)
                    .permissions(basicPermissions));

            rolesApi.createOrUpdateRole(new RoleEntry()
                    .name(adminRoleName)
                    .permissions(adminPermissions));

            CreateUserResponse basicUser = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(basicUserName)
                    .type(CreateUserRequest.TypeEnum.LOCAL)
                    .roles(Collections.singleton(basicRoleName)));
            assertTrue(basicUser.getOk());

            CreateUserResponse adminUser = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(adminUserName)
                    .type(CreateUserRequest.TypeEnum.LOCAL)
                    .roles(Collections.singleton(adminRoleName)));
            assertTrue(adminUser.getOk());

            UserEntry basicUserEntry = usersApi.findByUsername(basicUserName);
            assertNotNull(basicUserEntry);
            assertEquals(1, basicUserEntry.getRoles().size());
            assertEquals(basicRoleName, basicUserEntry.getRoles().iterator().next().getName());

            UserEntry adminUserEntry = usersApi.findByUsername(adminUserName);
            assertNotNull(adminUserEntry);
            assertEquals(1, adminUserEntry.getRoles().size());
            assertEquals(adminRoleName, adminUserEntry.getRoles().iterator().next().getName());

            CreateApiKeyResponse basicApiKey = apiKeysApi.createUserApiKey(new CreateApiKeyRequest().username(basicUserName));
            CreateApiKeyResponse adminApiKey = apiKeysApi.createUserApiKey(new CreateApiKeyRequest().username(adminUserName));

            setApiKey(basicApiKey.getKey());
            OrganizationsApi orgApi = new OrganizationsApi(getApiClient());
            try {
                orgApi.createOrUpdateOrg(new OrganizationEntry().name("testOrg_" + randomString()));
                fail("Basic user should not be able to create organizations");
            } catch (ApiException e) {
                assertTrue(e.getMessage().contains("createOrg"));
            }

            setApiKey(adminApiKey.getKey());
            CreateOrganizationResponse orgResponse = orgApi.createOrUpdateOrg(new OrganizationEntry().name("testOrg_" + randomString()));
            assertTrue(orgResponse.getOk());

        } finally {
            resetApiKey();
            try {
                usersApi.deleteUser(usersApi.findByUsername(basicUserName).getId());
            } catch (Exception e) {
            }
            try {
                usersApi.deleteUser(usersApi.findByUsername(adminUserName).getId());
            } catch (Exception e) {
            }
            try {
                rolesApi.deleteRole(basicRoleName);
            } catch (Exception e) {
            }
            try {
                rolesApi.deleteRole(adminRoleName);
            } catch (Exception e) {
            }
        }
    }

    @Test
    public void testUserModificationWorkflows() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());
        RolesApi rolesApi = new RolesApi(getApiClient());

        String username = "modifyUser_" + randomString();
        String roleName1 = "role1_" + randomString();
        String roleName2 = "role2_" + randomString();

        try {
            rolesApi.createOrUpdateRole(new RoleEntry().name(roleName1));
            rolesApi.createOrUpdateRole(new RoleEntry().name(roleName2));

            CreateUserResponse cur = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(username)
                    .type(CreateUserRequest.TypeEnum.LOCAL)
                    .displayName("Original Name")
                    .email("original@example.com")
                    .roles(Collections.singleton(roleName1)));
            assertTrue(cur.getOk());

            UserEntry originalUser = usersApi.findByUsername(username);
            assertEquals("Original Name", originalUser.getDisplayName());
            assertEquals("original@example.com", originalUser.getEmail());
            assertEquals(1, originalUser.getRoles().size());

            usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(username)
                    .type(CreateUserRequest.TypeEnum.LOCAL)
                    .displayName("Modified Name")
                    .email("modified@example.com")
                    .roles(Collections.singleton(roleName2)));

            UserEntry modifiedUser = usersApi.findByUsername(username);
            assertEquals("Modified Name", modifiedUser.getDisplayName());
            assertEquals("modified@example.com", modifiedUser.getEmail());
            assertEquals(1, modifiedUser.getRoles().size());
            assertEquals(roleName2, modifiedUser.getRoles().iterator().next().getName());

        } finally {
            try {
                usersApi.deleteUser(usersApi.findByUsername(username).getId());
            } catch (Exception e) {
            }
            try {
                rolesApi.deleteRole(roleName1);
            } catch (Exception e) {
            }
            try {
                rolesApi.deleteRole(roleName2);
            } catch (Exception e) {
            }
        }
    }

    @Test
    public void testUserDeactivationAndReactivationFlows() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());
        String username = "deactivateUser_" + randomString();
        try {
            CreateUserResponse cur = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(username)
                    .type(CreateUserRequest.TypeEnum.LOCAL));
            assertTrue(cur.getOk());
            
            UserEntry user = usersApi.findByUsername(username);
            assertFalse(user.getDisabled());
            assertFalse(user.getPermanentlyDisabled());
            
            UserEntry disabledUser = usersApi.disableUser(user.getId(), false);
            assertNotNull(disabledUser);
            assertTrue(disabledUser.getDisabled());
            assertFalse(disabledUser.getPermanentlyDisabled());
            
            UserEntry permanentlyDisabledUser = usersApi.disableUser(user.getId(), true);
            assertNotNull(permanentlyDisabledUser);
            assertTrue(permanentlyDisabledUser.getDisabled());
            assertTrue(permanentlyDisabledUser.getPermanentlyDisabled());
        } finally {
            try {
                usersApi.deleteUser(usersApi.findByUsername(username).getId());
            } catch (Exception e) {}
        }
    }

    @Test
    public void testPermissionAndRoleAssignmentScenarios() throws Exception {
        UsersApi usersApi = new UsersApi(getApiClient());
        RolesApi rolesApi = new RolesApi(getApiClient());
        TeamsApi teamsApi = new TeamsApi(getApiClient());
        OrganizationsApi orgApi = new OrganizationsApi(getApiClient());

        String orgName = "testOrg_" + randomString();
        String teamName = "testTeam_" + randomString();
        String roleName1 = "role1_" + randomString();
        String roleName2 = "role2_" + randomString();
        String userName = "testUser_" + randomString();

        try {
            CreateOrganizationResponse orgResponse = orgApi.createOrUpdateOrg(new OrganizationEntry().name(orgName));
            assertTrue(orgResponse.getOk());

            Set<String> permissions1 = new HashSet<>();
            permissions1.add("createProject");
            permissions1.add("updateProject");

            Set<String> permissions2 = new HashSet<>();
            permissions2.add("createOrg");
            permissions2.add("updateOrg");

            rolesApi.createOrUpdateRole(new RoleEntry()
                    .name(roleName1)
                    .permissions(permissions1));

            rolesApi.createOrUpdateRole(new RoleEntry()
                    .name(roleName2)
                    .permissions(permissions2));

            CreateUserResponse userResponse = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(userName)
                    .type(CreateUserRequest.TypeEnum.LOCAL)
                    .roles(Collections.singleton(roleName1)));
            assertTrue(userResponse.getOk());

            UserEntry user = usersApi.findByUsername(userName);
            assertEquals(1, user.getRoles().size());
            assertEquals(roleName1, user.getRoles().iterator().next().getName());

            usersApi.updateUserRoles(userName, new UpdateUserRolesRequest()
                    .roles(Collections.singleton(roleName2)));

            UserEntry updatedUser = usersApi.findByUsername(userName);
            assertEquals(1, updatedUser.getRoles().size());
            assertEquals(roleName2, updatedUser.getRoles().iterator().next().getName());

            CreateTeamResponse teamResponse = teamsApi.createOrUpdateTeam(orgName, new TeamEntry()
                    .name(teamName)
                    .members(Collections.singletonMap(userName, TeamRole.MEMBER)));
            assertTrue(teamResponse.getOk());

            TeamEntry team = teamsApi.getTeam(orgName, teamName);
            assertNotNull(team);
            assertTrue(team.getMembers().containsKey(userName));

        } finally {
            try {
                usersApi.deleteUser(usersApi.findByUsername(userName).getId());
            } catch (Exception e) {}
            try {
                teamsApi.deleteTeam(orgName, teamName);
            } catch (Exception e) {}
            try {
                orgApi.deleteOrg(orgName);
            } catch (Exception e) {}
            try {
                rolesApi.deleteRole(roleName1);
            } catch (Exception e) {}
            try {
                rolesApi.deleteRole(roleName2);
            } catch (Exception e) {}
        }
    }

    @Test
    public void testLdapIntegrationScenarios() throws Exception {
        assumeTrue(System.getenv("IT_LDAP_URL") != null);

        UsersApi usersApi = new UsersApi(getApiClient());
        ApiKeysApi apiKeysApi = new ApiKeysApi(getApiClient());

        String ldapUsername = "ldapUser_" + randomString();
        String ldapGroupName = "ldapGroup_" + randomString();

        try {
            createLdapUser(ldapUsername);
            createLdapGroupWithUser(ldapGroupName, ldapUsername);

            CreateUserResponse ldapUserResponse = usersApi.createOrUpdateUser(new CreateUserRequest()
                    .username(ldapUsername)
                    .type(CreateUserRequest.TypeEnum.LDAP));
            assertTrue(ldapUserResponse.getOk());

            UserEntry ldapUser = usersApi.findByUsername(ldapUsername);
            assertNotNull(ldapUser);
            assertEquals(CreateUserRequest.TypeEnum.LDAP.toString(), ldapUser.getType().toString());

            CreateApiKeyResponse apiKeyResponse = apiKeysApi.createUserApiKey(new CreateApiKeyRequest()
                    .username(ldapUsername)
                    .userType(CreateApiKeyRequest.UserTypeEnum.LDAP));
            assertTrue(apiKeyResponse.getOk());

            UserEntry caseInsensitiveUser = usersApi.findByUsername(ldapUsername.toLowerCase());
            assertNotNull(caseInsensitiveUser);
            assertEquals(ldapUsername.toLowerCase(), caseInsensitiveUser.getName());

            UserEntry disabledLdapUser = usersApi.disableUser(ldapUser.getId(), false);
            assertNotNull(disabledLdapUser);
            assertTrue(disabledLdapUser.getDisabled());
            assertFalse(disabledLdapUser.getPermanentlyDisabled());

        } finally {
            try {
                usersApi.deleteUser(usersApi.findByUsername(ldapUsername).getId());
            } catch (Exception e) {}
        }
    }

    private static void createLdapUser(String username) throws Exception {
        assumeTrue(System.getenv("IT_LDAP_URL") != null);
        
        DirContext ldapCtx = LdapIT.createContext();
        String userOu = "ou=users,dc=example,dc=org";
        String dn = "uid=" + username + "," + userOu;
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

    private static void createLdapGroupWithUser(String groupName, String username) throws Exception {
        assumeTrue(System.getenv("IT_LDAP_URL") != null);
        
        DirContext ldapCtx = LdapIT.createContext();
        String groupOu = "ou=groups,dc=example,dc=org";
        String userOu = "ou=users,dc=example,dc=org";
        String groupDn = "cn=" + groupName + "," + groupOu;
        String userDn = "uid=" + username + "," + userOu;
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
