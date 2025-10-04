# Auth0 Passkey My Account Enrolment with Custom Database

## Overview

This Auth0 Action implements a workaround solution that enables passkey enrollment for users authenticating through a custom database connection with import mode turned off.

**The Problem:** Auth0's standard passkey enrollment flow works during Universal Login directly, however the My Account API currently does not support passkey enrollment via API for custom databases with import mode turned off.

**The Solution:** This action leverages Auth0's extensibility to:
1. Create a secondary identity in a workaround database (`noimport-workaround-db`)
2. Use a custom Auth0 form to enroll passkeys against this secondary `_pk` identity
3. Automatically migrate the enrolled passkey from the secondary identity to the primary custom database identity
4. Enable users to authenticate with their passkey against their primary custom database account

**The Result:** Users with custom database accounts (import mode off) can enroll passkeys through an Auth0 form and subsequently use those passkeys to authenticate with their primary account.

## Trigger

**Post Login** - This action executes during the authentication flow after a user successfully logs in.

## Dependencies

The action requires the following npm packages:
- `@auth0/auth0` - For Auth0 Management Client and Authentication Client
- `axios` - For making HTTP requests during token exchange

## Required Secrets

Configure these secrets in your Auth0 Action settings:

| Secret Name | Description | Example |
|------------|-------------|---------|
| `MANAGEMENT_API_DOMAIN` | Your Auth0 tenant domain | `your-tenant.us.auth0.com` |
| `MANAGEMENT_API_CLIENT_ID` | Client ID of M2M Application with Management API scopes | `abc123...` |
| `MANAGEMENT_API_CLIENT_SECRET` | Client Secret of the M2M Application | `secret123...` |
| `CTE_CLIENT_ID` | Client ID for token exchange M2M application | `xyz789...` |
| `CTE_CLIENT_SECRET` | Client Secret for token exchange M2M application | `secret789...` |
| `MY_ACCOUNT_API_AUDIENCE_CUSTOM_DOMAIN` | Audience URI for token exchange | `https://auth.custom.com/me/` |
| `AUTH0_CUSTOM_DOMAIN` | Your Auth0 custom domain | `auth.custom.com` |

## Action Structure

The action is divided into four main parts:

### Part 1: Custom DB WorkAround - Create and Link _pk Identity

This section handles the creation of a workaround identity for users who need passkey support.

#### Key Functions:

**`hasPasskeyIdentity(user)`**
- Checks if a user has an identity with a `user_id` ending in "_pk"
- Returns `true` if found, `false` otherwise
- Used to determine if the workaround identity has already been created

**`generateRandomPassword()`**
- Generates a secure 24-character random password
- Uses alphanumeric characters and special symbols
- Used when creating the workaround database user

**`generatePasskeyUserId(primaryUserId)`**
- Takes the primary user's `user_id` (e.g., `auth0|12345`)
- Removes the `auth0|` prefix
- Appends `_pk` suffix (e.g., `12345_pk`)
- Returns the formatted passkey user_id

**`getManagementAccessToken(event, api)`**
- Fetches an access token for the Auth0 Management API
- Implements caching with 24-hour TTL to minimize API calls
- Uses the Authentication Client with client credentials grant
- Stores token in the action cache for reuse

**`linkIdentities(event, api, primaryUserId, secondaryIdentity)`**
- Links a secondary identity to a primary user account
- Makes direct API call to `/api/v2/users/{id}/identities`
- Handles "already linked" scenarios gracefully
- Returns updated list of identities for the primary user

**`createAndLinkPasskeyWorkaroundUser(event, api, primaryUserId)`**
- Creates a new user in the `noimport-workaround-db` connection
- Sets the custom `user_id` with "_pk" suffix
- Marks email as verified and sets random password
- Automatically links the new identity to the primary user

### Part 2: Token Exchange

This section performs an OAuth token exchange to obtain a token with specific permissions.

#### Key Functions:

**`getUserMyAPToken(event)`**
- Executes token exchange using the `urn:ietf:params:oauth:grant-type:token-exchange` grant type
- Uses M2M client credentials for authentication
- Requests scope: `create:me:authentication_methods`
- Subject token is the user's `user_id`
- Returns access token on success, `null` on failure

### Part 3: "On Continue" Passkey Fix - Transfer Passkeys from _pk Identity to Primary User

This section handles the migration of passkeys from the workaround _pk identity to the primary user identity.

#### Key Functions:

**`getAuthenticationMethods(token, userId, domain)`**
- Retrieves all authentication methods for a specific user
- Uses Management API `/api/v2/users/{id}/authentication-methods` endpoint
- Returns array of authentication method objects

**`deleteAuthenticationMethod(token, userId, methodId, domain)`**
- Deletes a specific authentication method by ID
- Uses DELETE request to Management API
- Required before recreating the passkey with updated identity

**`createAuthenticationMethod(token, userId, methodData, domain)`**
- Creates a new authentication method for a user
- Uses POST request to Management API
- Returns the newly created authentication method object

**`fixPasskeys(event, api, primaryUserId)`**
- Main orchestration function for passkey migration
- Finds all passkeys with `identity_user_id` ending in "_pk"
- For each passkey:
  1. Extracts required fields (type, key_id, credential_device_type, etc.)
  2. Updates `identity_user_id` by removing "_pk" suffix
  3. Deletes the original passkey
  4. Recreates it with the updated identity_user_id
  5. Waits 1 second between delete and create for propagation
- Returns object with:
  - `passkeysProcessed`: Number of passkeys that were processed
  - `results`: Array of operation results for each passkey

## Custom Form Flow (Step 4 - Passkey Enrollment)

After the action renders the custom prompt in Step 3, the `onExecutePostLogin` handler completes and the user is redirected to an Auth0 Universal Login custom form. This is Step 4 of the full flow - what happens in the form before the user returns to trigger Step 5 (`onContinuePostLogin`):

### Form Configuration

The custom form (ID: `ap_oVkpPNyPhkixNKZVno3cVa`) contains a custom field component that handles passkey registration.

#### Configuration Parameters Passed to Form:
- `auth0Domain` - The Auth0 custom domain
- `email` - User's email address
- `myAccountAt` - The access token from Step 2 (with `create:me:authentication_methods` scope)
- `mainUserID` - The primary user's `user_id`
- `secondaryConnectionName` - The workaround database connection name (`noimport-workaround-db`)

#### Form Settings:
- `ALLOW_DUPLICATE_PASSKEYS`: Set to `false` for production (prevents registering same device multiple times)
- `ALLOW_AUTO_PROCEED`: Set to `true` to automatically continue after successful registration

### Passkey Registration Process in Form

**Step 1: User Clicks "Create a Passkey" Button**
- Form displays message: "Starting passkey registration process..."
- Button is disabled to prevent double-clicks

**Step 2: Request Challenge from Auth0**
```javascript
POST https://{auth0Domain}/me/v1/authentication-methods
Headers: 
  - Content-Type: application/json
  - Authorization: Bearer {myAccountAt}
Body:
  {
    "type": "passkey",
    "connection": "noimport-workaround-db",
    "identity_user_id": "{mainUserID without auth0| prefix}_pk"
  }
```

Response contains:
- `authn_params_public_key` - WebAuthn challenge and parameters
- `auth_session` - Session token for verification step

**Step 3: Browser WebAuthn API Call**
- Form displays: "Requesting passkey creation on your device..."
- Converts Base64URL challenge to ArrayBuffer
- Calls `navigator.credentials.create()` with:
  - Challenge from Auth0
  - Relying Party (RP) information
  - User information (id, name, displayName)
  - `requireResidentKey: true` (for discoverable credentials)
  - `userVerification: 'preferred'`
  - `excludeCredentials` (if `ALLOW_DUPLICATE_PASSKEYS` is false)

**Step 4: User Completes Device Biometric/PIN**
- Browser shows native passkey UI
- User authenticates with Face ID, Touch ID, Windows Hello, or security key
- Browser creates credential and returns attestation

**Step 5: Verify Passkey with Auth0**
```javascript
POST https://{auth0Domain}/me/v1/authentication-methods/passkey|new/verify
Headers:
  - Content-Type: application/json
  - Authorization: Bearer {myAccountAt}
Body:
  {
    "auth_session": "{auth_session from step 2}",
    "authn_response": {
      "id": "{Base64URL credential ID}",
      "rawId": "{Base64URL raw credential ID}",
      "type": "public-key",
      "authenticatorAttachment": "{platform|cross-platform}",
      "response": {
        "clientDataJSON": "{Base64URL client data}",
        "attestationObject": "{Base64URL attestation}"
      }
    }
  }
```

**Step 6: Success Handling**
- Form displays: "Passkey registered successfully!"
- Extracts and decodes `id_token` from verification response
- Sets hidden field `enrolled_user_id` with subject from ID token
- Hides "Create a Passkey" button

**Step 7: Auto-Proceed (if enabled)**
- Form displays: "Success! Proceeding automatically..."
- Waits 1 second
- Calls `context.form.goForward()` to submit form
- User is sent back to the action's `onContinuePostLogin` handler

**Alternative Step 7: Manual Continue (if auto-proceed disabled)**
- Form shows "Continue" button
- User clicks "Continue" to proceed
- Calls `context.form.goForward()` to submit form

### Error Handling in Form

**NotAllowedError (User Cancelled)**
- Message: "Passkey registration was cancelled. Click the button to try again."
- Re-enables registration button for retry

**Challenge Request Failed**
- Message: "Failed to retrieve challenge: {error details}"
- Error displayed in red with error icon

**Verification Failed**
- Message: "Passkey verification failed: {error details}"
- Error displayed in red with error icon

**Other Errors**
- Message: "Passkey registration failed: {error message}"
- Re-enables registration button for retry

### Important Notes About Form Behavior

1. **Passkey is Created on _pk Identity**: The form specifically sets `identity_user_id` to `{userID}_pk`, ensuring the passkey is initially associated with the workaround database identity, not the primary user.

2. **Token Validation**: The form uses the `myAccountAt` token passed from Step 2. This token must have the `create:me:authentication_methods` scope to successfully create the passkey.

3. **State Management**: The form tracks `passkeyRegisteredSuccessfully` to prevent re-enabling the registration button after success.

4. **No Password Fallback**: The "Set a password instead" button is commented out in the current implementation, forcing passkey-only enrollment.

5. **Hidden Field**: The form sets a hidden field `enrolled_user_id` which could be used for additional verification in the continue handler if needed.

### Form-to-Action Transition

Once the user clicks "Continue" (either automatically or manually):
1. Form calls `context.form.goForward()`
2. Auth0 completes Step 4 and moves to Step 5
3. Action's `onContinuePostLogin` handler is triggered
4. Passkey transfer process begins (see Step 5 below)

## Execution Flow

### `onExecutePostLogin` Handler

This is the main entry point when a user logs in.

#### Early Exit Conditions:

1. **Token Exchange Protocol Check**
   - Skips if `event.transaction.protocol === "oauth2-token-exchange"`
   - Prevents infinite loops during token exchange operations

2. **Passkey Authentication Check**
   - Skips if user authenticated using a passkey (`event.authentication.methods` contains "passkey")
   - No need to run the workflow if already using passkey

3. **Secrets Validation**
   - Skips if required Management API secrets are missing
   - Ensures action can function properly

#### Execution Steps:

**Step 1: Create and Link _pk Identity (if needed)**
```
IF user does NOT have passkey identity (_pk):
  - Create new user in 'noimport-workaround-db'
  - Generate user_id with "_pk" suffix
  - Link secondary identity to primary user
ELSE:
  - Skip creation (user already has _pk identity)
```

**Step 2: Perform Token Exchange**
```
- Call getUserMyAPToken()
- Request token with 'create:me:authentication_methods' scope
- IF token exchange fails:
    - Deny access with error: "token_exchange_failed"
```

**Step 3: Render Custom Prompt**
```
- Call api.prompt.render('ap_oVkpPNyPhkixNKZVno3cVa')
- Pass token in vars: { api_token: myAccountToken }
- onExecutePostLogin handler completes
- User is redirected to custom Auth0 Universal Login form
```

**Step 4: Custom Form Flow (User Enrolls Passkey)**
```
- User interacts with custom form (see detailed Custom Form Flow section below)
- Form uses the token to call Auth0 /me API
- User enrolls passkey via WebAuthn
- Passkey is stored with _pk identity
- User clicks "Continue" 
- Form calls context.form.goForward()
```

**Step 5: onContinuePostLogin Handler Executes**
```
- Action resumes with onContinuePostLogin handler
- Passkey transfer process begins (see below)
```

### `onContinuePostLogin` Handler

This is **Step 5** of the full flow, which executes after the user completes the custom form in Step 4.

#### Execution Steps:

**Step 5: Fix Passkey Associations**
```
- Call fixPasskeys() function
- Find all passkeys with identity_user_id ending in "_pk"
- For each passkey:
    1. Delete original passkey
    2. Recreate with updated identity_user_id (removes "_pk")
- Log results of all operations
```

**Step 2: Complete Login**
```
- Step 5 completes successfully
- User login flow continues normally
```

## Workflow Diagram

```
User Logs In
    ↓
[Early Exit Checks]
    ↓
════════════════════════════════════════════════════════════════
STEP 1: Create and Link _pk Identity (if needed)
════════════════════════════════════════════════════════════════
Does user have _pk identity?
    ├── NO → Create user in noimport-workaround-db
    │         ↓
    │        Link _pk identity to primary user
    │
    └── YES → Skip creation
    ↓
════════════════════════════════════════════════════════════════
STEP 2: Token Exchange
════════════════════════════════════════════════════════════════
Obtain access token with 'create:me:authentication_methods' scope
    ↓
    ├── Success → Continue
    └── Failure → Deny access
    ↓
════════════════════════════════════════════════════════════════
STEP 3: Render Custom Prompt
════════════════════════════════════════════════════════════════
Call api.prompt.render('ap_oVkpPNyPhkixNKZVno3cVa')
Pass token to form
onExecutePostLogin completes
    ↓
User redirected to custom form
    ↓
════════════════════════════════════════════════════════════════
STEP 4: Custom Form Flow (Passkey Enrollment)
════════════════════════════════════════════════════════════════
    ╔═══════════════════════════════════════════════════════════╗
    ║              CUSTOM FORM PASSKEY ENROLLMENT               ║
    ╠═══════════════════════════════════════════════════════════╣
    ║ 1. User sees "Create a Passkey" button                    ║
    ║ 2. User clicks button                                     ║
    ║ 3. Form requests challenge from Auth0 /me API             ║
    ║    - POST /me/v1/authentication-methods                   ║
    ║    - identity_user_id: {userID}_pk                        ║
    ║ 4. Browser shows native passkey UI                        ║
    ║ 5. User completes biometric/PIN verification              ║
    ║ 6. Form verifies passkey with Auth0                       ║
    ║    - POST /me/v1/authentication-methods/passkey|new/verify║
    ║ 7. Passkey created on _pk identity ✓                      ║
    ║ 8. Form shows success message                             ║
    ║ 9. Auto-proceed after 1 second (or manual Continue)       ║
    ║    - Calls context.form.goForward()                       ║
    ╚═══════════════════════════════════════════════════════════╝
    ↓
════════════════════════════════════════════════════════════════
STEP 5: onContinuePostLogin (Passkey Transfer)
════════════════════════════════════════════════════════════════
Action resumes
    ↓
Get all authentication methods for user
    ↓
Find passkeys with identity_user_id ending in "_pk"
    ↓
For each _pk passkey found:
    ├── Extract passkey data (key_id, public_key, etc.)
    ├── Update identity_user_id (remove "_pk" suffix)
    ├── Delete original passkey from user
    ├── Wait 1 second for propagation
    ├── Recreate passkey with updated identity_user_id
    └── Log success/failure
    ↓
All passkeys migrated from _pk identity → primary identity
    ↓
════════════════════════════════════════════════════════════════
Login completes successfully
════════════════════════════════════════════════════════════════
```

## Error Handling

### Non-Blocking Errors
- Passkey fix errors in `onContinuePostLogin` are logged but don't deny access
- User can still complete login even if passkey migration fails

### Blocking Errors
- Token exchange failure denies access with error code `token_exchange_failed`
- Missing Management API secrets skips action execution entirely

### Graceful Degradation
- "Already linked" errors during identity linking are handled gracefully
- Existing _pk identities are detected and creation is skipped

## Logging

The action provides comprehensive logging at each step:

- **Action Entry**: "Combined Action: Starting execution."
- **Identity Check**: "Passkey identity found: {id}" or "No passkey identity (_pk) found for user."
- **Identity Creation**: "Creating new user on connection..." and "Linking successful..."
- **Token Exchange**: "Preparing for token exchange." and "Token exchange successful."
- **Prompt Render**: "All steps completed successfully. Rendering custom prompt."
- **Passkey Fix**: "Found X passkey(s) with _pk identity_user_id to fix."
- **Results**: Detailed JSON of all passkey operations

## Security Considerations

1. **Token Caching**: Management API tokens are cached for up to 24 hours to reduce API calls
2. **Password Security**: Generated passwords are 24 characters with mixed character types
3. **Scope Limitation**: Token exchange requests only the specific scope needed
4. **Error Suppression**: Sensitive error details are logged but not exposed to users

## Use Cases

This combined action is specifically designed for organizations that:

1. **Use Custom Database Connections with Import Mode Off**: Your user directory exists in an external database that Auth0 authenticates against, but you don't import users into Auth0's database.

2. **Want to Enable Passkey Authentication**: You want to offer modern, passwordless authentication using passkeys (WebAuthn) to your users.

3. **Face the Standard Limitation**: Auth0's native passkey enrollment only works during Universal Login directly, which doesn't support custom databases with import mode off in the typical workflow.

4. **Need a Workaround Solution**: This action provides a creative workaround by:
   - Creating a secondary "shadow" identity that supports passkey storage
   - Using Auth0's custom forms and Management API to enroll passkeys
   - Migrating the passkey to work with the primary custom database identity
   - All achieved through Auth0's native extensibility without external dependencies

**Real-World Scenario**: A company has 100,000 users in their own database system. They authenticate these users through Auth0's custom database connection but don't want to migrate all user data into Auth0. They want to offer passkey login to improve security and user experience. This action enables that capability despite the architectural constraint.

## Maintenance Notes

- Review logs regularly to monitor passkey fix success rates
- Monitor cache hit rates for Management API token caching
- Update form ID if the custom prompt is recreated
- Ensure M2M applications have correct scopes:
  - Management API: `read:users`, `update:users`, `create:users`, `read:authentication_methods`, `update:authentication_methods`, `delete:authentication_methods`
  - Token Exchange: `create:me:authentication_methods`

## Version History

**Current Version**: Combined Action v1.0
- Merged three separate actions into unified flow
- Removed deprecated external API call
- Updated form ID to latest version (ap_oVkpPNyPhkixNKZVno3cVa)
- Renamed secrets for clarity (M2M → CTE, AUTH0_DOMAIN → AUTH0_CUSTOM_DOMAIN)

## Architecture Innovation

This solution showcases Auth0's extensibility and demonstrates how creative use of platform features can overcome architectural constraints:

**Auth0 Features Leveraged:**
- **Actions (Post-Login)**: Custom logic execution during authentication flow
- **Custom Forms**: User interface for passkey enrollment
- **Management API**: Programmatic user and identity management
- **Account Linking**: Multiple identities consolidated under one user profile
- **Token Exchange**: Secure token acquisition with specific scopes
- **WebAuthn/Passkey Support**: Modern passwordless authentication

**Workaround Strategy:**
Rather than requiring changes to Auth0's core platform or external infrastructure, this solution works entirely within Auth0's existing capabilities by:
1. Using a secondary database connection as a "passkey storage layer"
2. Temporarily associating passkeys with the secondary identity during enrollment
3. Migrating passkeys to the primary identity post-enrollment
4. Maintaining a single user profile with multiple linked identities

This approach demonstrates that with thoughtful use of Auth0's extensibility, organizations can implement advanced authentication scenarios even when standard workflows don't directly support their architecture.
