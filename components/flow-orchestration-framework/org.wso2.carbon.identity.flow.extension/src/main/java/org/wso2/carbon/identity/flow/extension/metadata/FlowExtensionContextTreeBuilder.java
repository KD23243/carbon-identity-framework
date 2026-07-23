/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.flow.extension.metadata;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.flow.extension.FlowExtensionConstants.ContextTree;
import org.wso2.carbon.identity.flow.extension.FlowExtensionConstants.FlowContextPaths;
import org.wso2.carbon.identity.flow.extension.internal.FlowExtensionDataHolder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Builds the controlled Flow Extension context tree returned by the metadata endpoint.
 * The set of exposed attributes is governed at code level by this builder so the frontend
 * receives the user/flow tree shape the Console UI expects.
 */
public class FlowExtensionContextTreeBuilder {

    private static final Log LOG = LogFactory.getLog(FlowExtensionContextTreeBuilder.class);

    /**
     * Build the metadata response for the given flow type.
     *
     * @param flowType the flow type (null → default tree).
     * @return a fully populated metadata DTO.
     */
    public FlowExtensionContextTreeMetadata build(String flowType) {

        List<FlowExtensionContextTreeNode> tree = new ArrayList<>();
        tree.add(buildUserNode());
        tree.add(buildTenantNode());
        tree.add(buildApplicationNode());
        tree.add(buildOrganizationNode());
        tree.add(buildFlowNode());

        return new FlowExtensionContextTreeMetadata(
                flowType,
                tree,
                true,
                allowReadOnlyClaimsModification(flowType));
    }

    /**
     * Whether the Console UI may permit MODIFY on read-only claims for this flow type.
     * Hardcoded enumerative mapping so that any future flow type defaults to false until
     * explicitly added here.
     *
     * <p>The default tree (null flowType) returns true — matches current behaviour for the
     * connection-level access-config editor which doesn't yet know which flow the action
     * will be wired into.</p>
     */
    static boolean allowReadOnlyClaimsModification(String flowType) {
        return flowType == null
                || ContextTree.FLOW_REGISTRATION.equals(flowType)
                || ContextTree.FLOW_INVITED_USER_REGISTRATION.equals(flowType);
    }

    private FlowExtensionContextTreeNode buildUserNode() {

        List<FlowExtensionContextTreeNode> children = new ArrayList<>();

        children.add(FlowExtensionContextTreeNode.builder()
                .key("id")
                .title("User ID")
                .path(FlowContextPaths.USER_ID_PATH)
                .dataType(ContextTree.DATA_TYPE_STRING)
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .replaceable(false)
                .build());
        children.add(FlowExtensionContextTreeNode.builder()
                .key("username")
                .title("Username")
                .path(FlowContextPaths.USER_USERNAME_PATH)
                .dataType(ContextTree.DATA_TYPE_STRING)
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .replaceable(false)
                .build());
        children.add(FlowExtensionContextTreeNode.builder()
                .key("userStoreDomain")
                .title("User Store Domain")
                .path(FlowContextPaths.USER_STORE_DOMAIN_PATH)
                .dataType(ContextTree.DATA_TYPE_STRING)
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .replaceable(false)
                .build());

        children.add(FlowExtensionContextTreeNode.builder()
                .key("claims")
                .title("Claims")
                .path("/user/claims")
                .dataType("Map<String, String>")
                .nodeType(ContextTree.NODE_MAP)
                .allowedOperations(Arrays.asList(ContextTree.OP_EXPOSE, ContextTree.OP_MODIFY))
                .dynamicEntryAllowed(true)
                .dynamicEntryType("String")
                .children(buildClaimChildren())
                .build());

        List<FlowExtensionContextTreeNode> credentialsChildren = new ArrayList<>();
        credentialsChildren.add(FlowExtensionContextTreeNode.builder()
                .key("password")
                .title("Password")
                .path(FlowContextPaths.USER_CREDENTIALS_PATH_PREFIX + "password")
                .dataType("char[]")
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(Arrays.asList(ContextTree.OP_EXPOSE, ContextTree.OP_MODIFY))
                .build());
        children.add(FlowExtensionContextTreeNode.builder()
                .key("credentials")
                .title("Credentials")
                .path(FlowContextPaths.USER_CREDENTIALS_PATH_PREFIX)
                .dataType("Map<String, char[]>")
                .nodeType(ContextTree.NODE_MAP)
                .allowedOperations(Arrays.asList(ContextTree.OP_EXPOSE, ContextTree.OP_MODIFY))
                .dynamicEntryAllowed(false)
                .children(credentialsChildren)
                .build());

        return FlowExtensionContextTreeNode.builder()
                .key("user")
                .title("User")
                .path(FlowContextPaths.USER_PREFIX)
                .dataType("")
                .nodeType(ContextTree.NODE_OBJECT)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .children(children)
                .build();
    }

    /**
     * Build the claims leaf nodes from the tenant's local claims.
     *
     * <p>Each claim becomes a {@code LEAF} addressed by the selector path
     * {@code /user/claims[uri=<claimUri>]} — the same form the executor
     * ({@code FlowExtensionRequestBuilder} / {@code FlowExtensionResponseProcessor}) resolves at
     * runtime. EXPOSE is always allowed; MODIFY is added only for writable (non read-only) claims,
     * leaving read-only claims to the {@code allowReadOnlyClaimsModification} gate.</p>
     *
     * <p>Degrades to an empty list — no enumerated claims, while free-text entry keeps working via
     * {@code dynamicEntryAllowed} — when the claim service is unavailable or errors.</p>
     */
    private List<FlowExtensionContextTreeNode> buildClaimChildren() {

        ClaimMetadataManagementService claimService =
                FlowExtensionDataHolder.getInstance().getClaimMetadataManagementService();
        if (claimService == null) {
            return Collections.emptyList();
        }
        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            List<LocalClaim> localClaims = claimService.getLocalClaims(tenantDomain);
            if (localClaims == null) {
                return Collections.emptyList();
            }
            List<FlowExtensionContextTreeNode> claimNodes = new ArrayList<>();
            for (LocalClaim claim : selectExposableClaims(localClaims)) {
                claimNodes.add(toClaimNode(claim));
            }
            claimNodes.sort(Comparator.comparing(FlowExtensionContextTreeNode::getTitle,
                    String.CASE_INSENSITIVE_ORDER));
            return claimNodes;
        } catch (ClaimMetadataException e) {
            LOG.error("Error while retrieving local claims for the Flow Extension context tree. "
                    + "Serving the tree without enumerated claims.", e);
            return Collections.emptyList();
        }
    }

    /**
     * Select which local claims are advertised under {@code /user/claims}.
     *
     * <p>TODO: restrict to the SCIM-level mutable claims. Until that logic lands, every local
     * claim is returned so the enumeration mechanism is exercised end to end. This is the single
     * seam for changing the claim set — {@link #buildClaimChildren()} handles node construction,
     * ordering and error handling around it.</p>
     *
     * @param localClaims all local claims for the tenant.
     * @return the subset of claims to expose in the context tree.
     */
    private List<LocalClaim> selectExposableClaims(List<LocalClaim> localClaims) {

        // TODO: filter to SCIM-level mutable claims.
        return localClaims;
    }

    /**
     * Convert a single {@link LocalClaim} to its context-tree leaf node.
     */
    private FlowExtensionContextTreeNode toClaimNode(LocalClaim claim) {

        String claimUri = claim.getClaimURI();
        String displayName = claim.getClaimProperty(ClaimConstants.DISPLAY_NAME_PROPERTY);
        boolean readOnly = Boolean.parseBoolean(claim.getClaimProperty(ClaimConstants.READ_ONLY_PROPERTY));
        boolean multiValued = Boolean.parseBoolean(claim.getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY));

        List<String> allowedOperations = readOnly
                ? Collections.singletonList(ContextTree.OP_EXPOSE)
                : Arrays.asList(ContextTree.OP_EXPOSE, ContextTree.OP_MODIFY);

        return FlowExtensionContextTreeNode.builder()
                .key(claimUri)
                .title(displayName != null && !displayName.trim().isEmpty() ? displayName : claimUri)
                .path(FlowContextPaths.USER_CLAIMS_SELECTOR_PREFIX + claimUri
                        + FlowContextPaths.USER_CLAIMS_SELECTOR_SUFFIX)
                .dataType(ContextTree.DATA_TYPE_STRING)
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(allowedOperations)
                .readOnly(readOnly)
                .replaceable(false)
                .multiValued(multiValued)
                .build();
    }

    private FlowExtensionContextTreeNode buildFlowNode() {

        List<FlowExtensionContextTreeNode> children = new ArrayList<>();
        children.add(readOnlyLeaf("flowType", "Flow Type", FlowContextPaths.FLOW_TYPE_PATH));
        children.add(readOnlyLeaf("portalUrl", "Portal URL", FlowContextPaths.FLOW_PORTAL_URL_PATH));
        return FlowExtensionContextTreeNode.builder()
                .key("flow")
                .title("Flow")
                .path(FlowContextPaths.FLOW_PREFIX)
                .dataType("")
                .nodeType(ContextTree.NODE_OBJECT)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .readOnly(true)
                .children(children)
                .build();
    }

    private FlowExtensionContextTreeNode buildTenantNode() {

        List<FlowExtensionContextTreeNode> children = new ArrayList<>();
        children.add(readOnlyLeaf("domain", "Tenant Domain", FlowContextPaths.TENANT_DOMAIN_PATH));
        return FlowExtensionContextTreeNode.builder()
                .key("tenant")
                .title("Tenant")
                .path(FlowContextPaths.TENANT_PREFIX)
                .dataType("")
                .nodeType(ContextTree.NODE_OBJECT)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .readOnly(true)
                .children(children)
                .build();
    }

    private FlowExtensionContextTreeNode buildApplicationNode() {

        List<FlowExtensionContextTreeNode> children = new ArrayList<>();
        children.add(readOnlyLeaf("id", "Application ID", FlowContextPaths.APPLICATION_ID_PATH));
        return FlowExtensionContextTreeNode.builder()
                .key("application")
                .title("Application")
                .path(FlowContextPaths.APPLICATION_PREFIX)
                .dataType("")
                .nodeType(ContextTree.NODE_OBJECT)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .readOnly(true)
                .children(children)
                .build();
    }

    private FlowExtensionContextTreeNode buildOrganizationNode() {

        List<FlowExtensionContextTreeNode> children = new ArrayList<>();
        children.add(readOnlyLeaf("id", "Organization ID", FlowContextPaths.ORGANIZATION_ID_PATH));
        children.add(readOnlyLeaf("name", "Organization Name", FlowContextPaths.ORGANIZATION_NAME_PATH));
        children.add(readOnlyLeaf("orgHandle", "Organization Handle", FlowContextPaths.ORGANIZATION_HANDLE_PATH));
        children.add(readOnlyLeaf("depth", "Organization Depth", FlowContextPaths.ORGANIZATION_DEPTH_PATH));
        return FlowExtensionContextTreeNode.builder()
                .key("organization")
                .title("Organization")
                .path(FlowContextPaths.ORGANIZATION_PREFIX)
                .dataType("")
                .nodeType(ContextTree.NODE_OBJECT)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .readOnly(true)
                .children(children)
                .build();
    }

    private FlowExtensionContextTreeNode readOnlyLeaf(String key, String title, String path) {

        return FlowExtensionContextTreeNode.builder()
                .key(key)
                .title(title)
                .path(path)
                .dataType(ContextTree.DATA_TYPE_STRING)
                .nodeType(ContextTree.NODE_LEAF)
                .allowedOperations(Collections.singletonList(ContextTree.OP_EXPOSE))
                .readOnly(true)
                .build();
    }
}
