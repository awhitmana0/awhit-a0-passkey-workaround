/**
 * Combined Auth0 Action: Custom DB WorkAround + Passkey Identity Check + Token Exchange
 * Trigger: Post Login
 * Dependencies: @auth0/auth0, axios
 * 
 * Secrets (configured in Auth0 Action dashboard):
 *  - MANAGEMENT_API_DOMAIN: Your Auth0 tenant domain (e.g., your-tenant.us.auth0.com)
 *  - MANAGEMENT_API_CLIENT_ID: Client ID of your M2M Application with appropriate scopes
 *  - MANAGEMENT_API_CLIENT_SECRET: Client Secret of that M2M Application
 *  - CTE_CLIENT_ID: The Client ID of your M2M application for token exchange
 *  - CTE_CLIENT_SECRET: The Client Secret of your M2M application for token exchange
 *  - MY_ACCOUNT_API_AUDIENCE_CUSTOM_DOMAIN: The audience URI for the token exchange - https://auth.custom.com/me/
 *  - AUTH0_CUSTOM_DOMAIN: Your Auth0 custom domain (e.g., 'auth.custom.com')
 */

const { ManagementClient, AuthenticationClient } = require('auth0');
const axios = require("axios");

// ============================================================================
// PART 1: Custom DB WorkAround - Create and Link _pk Identity
// ============================================================================

/**
 * Checks if the user has an identity with a user_id ending in "_pk".
 * @param {Object} user - The user object containing the identities array.
 * @returns {boolean} - Returns true if a "_pk" identity exists, false otherwise.
 */
const hasPasskeyIdentity = (user) => {
  if (!user || !Array.isArray(user.identities)) {
    return false;
  }
  
  const passkeyIdentity = user.identities.find(identity => 
    identity.user_id && identity.user_id.endsWith('_pk')
  );
  
  if (passkeyIdentity) {
    console.log(`Passkey identity found: ${passkeyIdentity.user_id}`);
    return true;
  }
  
  console.log('No passkey identity (_pk) found for user.');
  return false;
};

/**
 * Generates a strong, random password for newly created users.
 * @returns {string} A random password string.
 */
const generateRandomPassword = () => {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
  let password = "";
  for (let i = 0; i < 24; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
};

/**
 * Generates the passkey user_id by removing "auth0|" prefix and postpending "_pk".
 * @param {string} primaryUserId - The primary user's user_id.
 * @returns {string} The formatted passkey user_id.
 */
const generatePasskeyUserId = (primaryUserId) => {
  const baseUserId = primaryUserId.replace(/^auth0\|/, '');
  return `${baseUserId}_pk`;
};

/**
 * @constant {number} - TTL for Management API token cache (24 hours in seconds)
 */
const MANAGEMENT_TOKEN_TTL_SECONDS = 24 * 60 * 60;

/**
 * Fetches and caches a Management API access token.
 * @param {Event} event
 * @param {PostLoginAPI} api
 * @returns {Promise<string>} - Management API access token
 */
const getManagementAccessToken = async (event, api) => {
  const managementApiTokenCacheKey = `mgmt-api-token-${event.secrets.MANAGEMENT_API_CLIENT_ID}`;
  const { value: cachedAccessToken } = api.cache.get(managementApiTokenCacheKey) || {};

  if (cachedAccessToken) {
    console.log('Using cached Management API token.');
    return cachedAccessToken;
  }

  const authentication = new AuthenticationClient({
    domain: event.secrets.MANAGEMENT_API_DOMAIN,
    clientId: event.secrets.MANAGEMENT_API_CLIENT_ID,
    clientSecret: event.secrets.MANAGEMENT_API_CLIENT_SECRET
  });

  console.log('Requesting new Management API token from Auth0...');
  const response = await authentication.oauth.clientCredentialsGrant({
    audience: `https://${event.secrets.MANAGEMENT_API_DOMAIN}/api/v2/`,
  });

  const accessToken = response.data.access_token;
  const expiresIn = response.data.expires_in;

  if (!accessToken || typeof accessToken !== 'string') {
    console.error('Error: Access token is missing or invalid in Management API response.', response);
    throw new Error('Failed to obtain valid Management API access token.');
  }

  api.cache.set(managementApiTokenCacheKey, accessToken, {
    ttl: Math.min(expiresIn, MANAGEMENT_TOKEN_TTL_SECONDS)
  });
  console.log(`New Management API token obtained and cached for ${expiresIn} seconds (max ${MANAGEMENT_TOKEN_TTL_SECONDS}s).`);

  return accessToken;
};

/**
 * Links a secondary identity to a primary user using direct API call.
 * @param {Event} event
 * @param {PostLoginAPI} api
 * @param {string} primaryUserId - The user_id of the primary account.
 * @param {Object} secondaryIdentity - The identity object of the secondary account to link.
 * @returns {Promise<Array<Object>>} - The updated list of identities for the primary user.
 */
const linkIdentities = async (event, api, primaryUserId, secondaryIdentity) => {
  console.log(`Attempting to link primary user ${primaryUserId} with secondary identity (provider: ${secondaryIdentity.provider}, user_id: ${secondaryIdentity.user_id}).`);

  try {
    const token = await getManagementAccessToken(event, api);

    const linkResponse = await fetch(`https://${event.secrets.MANAGEMENT_API_DOMAIN}/api/v2/users/${encodeURIComponent(primaryUserId)}/identities`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        provider: secondaryIdentity.provider,
        user_id: secondaryIdentity.user_id
      })
    });

    if (!linkResponse.ok) {
      const errorData = await linkResponse.json();
      console.error('Management API linking error response:', JSON.stringify(errorData, null, 2));
      
      if (errorData.message && errorData.message.includes('is already linked')) {
        console.log('Account is already linked. Proceeding as successful link.');
        
        const getUserResponse = await fetch(`https://${event.secrets.MANAGEMENT_API_DOMAIN}/api/v2/users/${encodeURIComponent(primaryUserId)}?fields=identities&include_fields=true`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        const userData = await getUserResponse.json();
        return userData.identities || [];
      }
      
      throw new Error(`Failed to link identities: ${linkResponse.status} ${linkResponse.statusText}`);
    }

    const linkedIdentities = await linkResponse.json();

    if (!Array.isArray(linkedIdentities)) {
      console.error('Link API returned unexpected data structure (expected an array of identities):', linkedIdentities);
      throw new Error('Linking API did not return the expected array of user identities.');
    }

    console.log(`Linking successful. Primary user ${primaryUserId} now has ${linkedIdentities.length} identities.`);
    return linkedIdentities;

  } catch (error) {
    console.error('Unexpected error during linkIdentities:', error.message || error);
    throw error;
  }
};

/**
 * Creates a new user in the noimport-workaround-db and links it to the primary account.
 * @param {Event} event
 * @param {PostLoginAPI} api
 * @param {string} primaryUserId - The user_id of the primary account to link to.
 * @returns {Promise<void>}
 */
const createAndLinkPasskeyWorkaroundUser = async (event, api, primaryUserId) => {
  const connectionName = 'noimport-workaround-db';
  const desiredUserId = generatePasskeyUserId(primaryUserId);

  try {
    console.log(`Creating new user on connection '${connectionName}' with user_id: ${desiredUserId}...`);

    const token = await getManagementAccessToken(event, api);

    const createUserResponse = await fetch(`https://${event.secrets.MANAGEMENT_API_DOMAIN}/api/v2/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        user_id: desiredUserId,
        email: event.user.email,
        email_verified: true,
        password: generateRandomPassword(),
        connection: connectionName
      })
    });

    if (!createUserResponse.ok) {
      const errorData = await createUserResponse.json();
      console.error('Failed to create user:', JSON.stringify(errorData, null, 2));
      throw new Error(`Failed to create user: ${createUserResponse.status} ${createUserResponse.statusText}`);
    }

    const newUser = await createUserResponse.json();
    console.log(`New user created on ${connectionName}. Full user_id: ${newUser.user_id}`);

    const actualUserId = newUser.user_id.replace(/^auth0\|/, '');

    const secondaryIdentity = {
      user_id: actualUserId,
      provider: 'auth0',
      connection: connectionName
    };

    console.log(`Linking the new ${connectionName} user (${actualUserId}) to primary user (${primaryUserId}).`);
    await linkIdentities(event, api, primaryUserId, secondaryIdentity);
    console.log(`Linking ${connectionName} account successful.`);

  } catch (error) {
    console.error(`Error during ${connectionName} account creation and linking:`, error);
    throw error;
  }
};

// ============================================================================
// PART 3: Passkey Fix - Copy passkeys from _pk identity to primary user
// ============================================================================

/**
 * Gets authentication methods for a user.
 * @param {string} token - Management API access token
 * @param {string} userId - The user_id to get authentication methods for
 * @param {string} domain - Auth0 domain
 * @returns {Promise<Array>} - Array of authentication methods
 */
const getAuthenticationMethods = async (token, userId, domain) => {
  const response = await fetch(`https://${domain}/api/v2/users/${encodeURIComponent(userId)}/authentication-methods`, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!response.ok) {
    const errorData = await response.json();
    console.error('Failed to get authentication methods:', JSON.stringify(errorData, null, 2));
    throw new Error(`Failed to get authentication methods: ${response.status} ${response.statusText}`);
  }

  return await response.json();
};

/**
 * Deletes an authentication method.
 * @param {string} token - Management API access token
 * @param {string} userId - The user_id
 * @param {string} methodId - The authentication method ID to delete
 * @param {string} domain - Auth0 domain
 * @returns {Promise<void>}
 */
const deleteAuthenticationMethod = async (token, userId, methodId, domain) => {
  const response = await fetch(`https://${domain}/api/v2/users/${encodeURIComponent(userId)}/authentication-methods/${encodeURIComponent(methodId)}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!response.ok) {
    const errorData = await response.json();
    console.error('Failed to delete authentication method:', JSON.stringify(errorData, null, 2));
    throw new Error(`Failed to delete authentication method: ${response.status} ${response.statusText}`);
  }
};

/**
 * Creates an authentication method.
 * @param {string} token - Management API access token
 * @param {string} userId - The user_id
 * @param {Object} methodData - The authentication method data
 * @param {string} domain - Auth0 domain
 * @returns {Promise<Object>} - The created authentication method
 */
const createAuthenticationMethod = async (token, userId, methodData, domain) => {
  const response = await fetch(`https://${domain}/api/v2/users/${encodeURIComponent(userId)}/authentication-methods`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(methodData)
  });

  if (!response.ok) {
    const errorData = await response.json();
    console.error('Failed to create authentication method:', JSON.stringify(errorData, null, 2));
    throw new Error(`Failed to create authentication method: ${response.status} ${response.statusText}`);
  }

  return await response.json();
};

/**
 * Fixes passkeys by copying from _pk identity to primary user.
 * @param {Event} event
 * @param {PostLoginAPI} api
 * @param {string} primaryUserId - The primary user's user_id
 * @returns {Promise<Object>} - Results of the fix operation
 */
const fixPasskeys = async (event, api, primaryUserId) => {
  const token = await getManagementAccessToken(event, api);
  const domain = event.secrets.MANAGEMENT_API_DOMAIN;

  console.log(`Getting authentication methods for user: ${primaryUserId}`);
  const authMethods = await getAuthenticationMethods(token, primaryUserId, domain);

  // Find passkey methods that have identity_user_id ending with _pk
  const passkeyMethods = authMethods.filter(method =>
    method.type === 'passkey' &&
    method.identity_user_id &&
    method.identity_user_id.endsWith('_pk')
  );

  if (passkeyMethods.length === 0) {
    console.log('No passkey methods found with _pk identity_user_id. No action needed.');
    return { passkeysProcessed: 0, results: [] };
  }

  console.log(`Found ${passkeyMethods.length} passkey(s) with _pk identity_user_id to fix.`);

  const results = [];
  const requiredFields = ['type', 'key_id', 'credential_device_type', 'credential_backed_up',
                          'identity_user_id', 'user_agent', 'public_key', 'user_handle'];

  for (const passkeyMethod of passkeyMethods) {
    try {
      // Extract only the required fields
      const passkeyCopy = {};
      for (const field of requiredFields) {
        if (field in passkeyMethod) {
          passkeyCopy[field] = passkeyMethod[field];
        }
      }

      // Update identity_user_id to remove _pk suffix
      if (passkeyCopy.identity_user_id && passkeyCopy.identity_user_id.endsWith('_pk')) {
        passkeyCopy.identity_user_id = passkeyCopy.identity_user_id.slice(0, -3);
        console.log(`Updated identity_user_id from ${passkeyMethod.identity_user_id} to ${passkeyCopy.identity_user_id}`);
      }

      // Delete the existing passkey
      try {
        console.log(`Deleting passkey method ${passkeyMethod.id} from user ${primaryUserId}`);
        await deleteAuthenticationMethod(token, primaryUserId, passkeyMethod.id, domain);
        results.push({
          action: 'deleted',
          methodId: passkeyMethod.id,
          success: true
        });

        // Wait a moment for the delete to propagate
        await new Promise(resolve => setTimeout(resolve, 1000));

      } catch (error) {
        console.error(`Failed to delete passkey method ${passkeyMethod.id}:`, error.message);
        results.push({
          action: 'delete_failed',
          methodId: passkeyMethod.id,
          error: error.message
        });
        continue;
      }

      // Create the passkey with updated identity_user_id
      try {
        console.log(`Creating passkey method for user ${primaryUserId} with updated identity_user_id`);
        const createdMethod = await createAuthenticationMethod(token, primaryUserId, passkeyCopy, domain);
        results.push({
          action: 'created',
          methodId: createdMethod.id,
          success: true
        });
        console.log(`Successfully created passkey method ${createdMethod.id}`);
      } catch (error) {
        console.error(`Failed to create passkey method:`, error.message);
        results.push({
          action: 'create_failed',
          error: error.message,
          passkeyData: passkeyCopy
        });
      }

    } catch (error) {
      console.error(`Failed to process passkey method ${passkeyMethod.id}:`, error.message);
      results.push({
        action: 'process_failed',
        methodId: passkeyMethod.id,
        error: error.message
      });
    }
  }

  return {
    passkeysProcessed: passkeyMethods.length,
    results
  };
};

// ============================================================================
// PART 4: Token Exchange
// ============================================================================

/**
 * Executes a token exchange to acquire a new token with specific permissions.
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @returns {Promise<string|null>} - The access token if successful, otherwise null.
 */
async function getUserMyAPToken(event) {
  try {
    const url = `https://${event.secrets.AUTH0_CUSTOM_DOMAIN}/oauth/token`;

    const payload = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: event.secrets.CTE_CLIENT_ID,
      client_secret: event.secrets.CTE_CLIENT_SECRET,
      audience: event.secrets.MY_ACCOUNT_API_AUDIENCE_CUSTOM_DOMAIN,
      scope: 'create:me:authentication_methods',
      subject_token: event.user.user_id,
      subject_token_type: 'urn:cteforms'
    };
    
    console.log("Preparing for token exchange.");
    console.log(`Request URL: ${url}`);

    const options = {
      method: 'POST',
      url: url,
      headers: { 'content-type': 'application/json' },
      data: payload
    };

    const response = await axios.request(options);
    console.log("Token exchange successful. Access token acquired.");
    return response.data.access_token;

  } catch (error) {
    console.error("Error during token exchange:", error.message);
    if (error.response) {
      console.error("Response Status:", error.response.status);
      console.error("Response data:", JSON.stringify(error.response.data));
    }
    return null;
  }
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

/**
 * Handler that will be called during the execution of a PostLogin flow.
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  // EARLY EXIT: Skip for token exchange protocol (prevents infinite loops)
  if (event.transaction.protocol === "oauth2-token-exchange") {
    console.log("Action skipped: Protocol is 'oauth2-token-exchange'.");
    return;
  }

  // EARLY EXIT: Skip if passkey was used for authentication
  const passkeyUsed = event.authentication.methods.some(
    method => method.name === "passkey"
  );
  
  if (passkeyUsed) {
    console.log("Authentication method 'passkey' detected. Skipping entire Action.");
    return;
  }

  console.log('Combined Action: Starting execution.');

  // VALIDATION: Check for required Management API secrets
  if (
    !event.secrets.MANAGEMENT_API_DOMAIN ||
    !event.secrets.MANAGEMENT_API_CLIENT_ID ||
    !event.secrets.MANAGEMENT_API_CLIENT_SECRET
  ) {
    console.error('Action skipped: Missing Management API secrets.');
    return;
  }

  try {
    // ========================================================================
    // STEP 1: Create and Link _pk Identity (if needed)
    // ========================================================================
    
    if (!hasPasskeyIdentity(event.user)) {
      console.log('No passkey identity found. Creating and linking _pk identity...');
      await createAndLinkPasskeyWorkaroundUser(event, api, event.user.user_id);
      console.log('_pk identity creation and linking completed.');
    } else {
      console.log('User already has _pk identity. Skipping creation.');
    }

    // ========================================================================
    // STEP 2: Perform Token Exchange
    // ========================================================================
    
    const myAccountToken = await getUserMyAPToken(event);

    if (!myAccountToken) {
      console.error('Token exchange failed. Denying access.');
      return api.access.deny('token_exchange_failed: Could not retrieve the necessary access token.');
    }

    // ========================================================================
    // STEP 3: Render Custom Prompt with Token
    // ========================================================================
    
    console.log('All steps completed successfully. Rendering custom prompt.');
    api.prompt.render('ap_oVkpPNyPhkixNKZVno3cVa', {
      vars: {
        api_token: myAccountToken
      }
    });

    console.log('Combined Action: Execution completed successfully.');
    
  } catch (err) {
    console.error('Combined Action: Error during execution:', err);
    // Optionally deny access on critical errors:
    // api.access.deny('Action failed due to an unexpected error.');
  }
};

/**
 * Handler that will be called when the user continues after a prompt.
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onContinuePostLogin = async (event, api) => {
  console.log("User continued from the custom prompt. Starting passkey fix process.");
  
  try {
    const result = await fixPasskeys(event, api, event.user.user_id);
    
    if (result.passkeysProcessed > 0) {
      console.log(`Passkey Fix: Processed ${result.passkeysProcessed} passkey(s).`);
      console.log(`Results: ${JSON.stringify(result.results, null, 2)}`);
    } else {
      console.log('Passkey Fix: No passkeys needed fixing.');
    }
    
    console.log('Passkey Fix: Execution completed successfully.');
    
  } catch (err) {
    console.error('Passkey Fix: Error during execution:', err);
    // Don't deny access, just log the error
  }
};