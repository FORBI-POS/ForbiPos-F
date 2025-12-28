# Q/A — ForbiPos Frontend & Backend (Comprehensive)

This file contains 220 concise technical questions and answers covering architecture, auth, roles, state, backup flows, frontend/backend interactions, troubleshooting, and related topics for the Forbi POS project.

1. Q: What is the main purpose of the `authService.loginUser` function?
   A: To validate credentials, populate the user's role, generate a JWT containing user id and role, and return the user and token.

2. Q: Where is the JWT set as a cookie?
   A: In `controllers/authController.js` inside the `login` function with `res.cookie('jwt', token, ...)`.

3. Q: Why must frontend include `credentials: "include"` when logging in?
   A: So the browser stores the `Set-Cookie` header and sends the `jwt` cookie on subsequent cross-origin requests.

4. Q: What does `protect` middleware check?
   A: It checks for `req.cookies.jwt`, verifies the token, and attaches the authenticated `req.user` to the request.

5. Q: What response does `protect` send when no cookie is present?
   A: `401` with message `Not authorized, no token`.

6. Q: What response does `protect` send when token verification fails?
   A: `401` with message `Not authorized, token failed`.

7. Q: How does `authorize(...roles)` determine access?
   A: It reads `req.user.role` (string or object with `name`) and checks if it's included in the allowed roles; otherwise returns `403`.

8. Q: Why might `authorize('admin')` incorrectly block an admin user?
   A: Because `protect` may load `req.user.role` as an ObjectId (not populated) and the `authorize` check compares to strings.

9. Q: How to ensure `req.user.role` has a `name` property?
   A: Populate role when loading user in `protect` (e.g., `.populate('role')`).

10. Q: What does `loginUser` include in the JWT payload?
    A: `{ id: user._id, role: user.role }` where `user.role` was `.populate('role')` during login.

11. Q: If JWT contains a role object, is that safe to use for authorization?
    A: It's convenient but can become stale; it's safer to re-fetch role from DB in `protect` or verify minimal role info in token.

12. Q: How does the frontend download backups?
    A: The Settings page does a `fetch('/api/backup/export', { credentials: 'include' })`, then builds and downloads a JSON blob.

13. Q: Why is `sameSite` cookie attribute important here?
    A: `sameSite: 'strict'` can block cookies on cross-site requests during development (frontend and backend on different ports).

14. Q: What's the recommended `sameSite` value for local dev?
    A: `lax` is recommended for local cross-origin requests; `none` requires `secure: true` with HTTPS.

15. Q: Which server file registers backup routes?
    A: `server.js` mounts `/api/backup` via `app.use('/api/backup', require('./routes/backupRoutes'))`.

16. Q: What does `createBackup` return?
    A: JSON containing arrays for products, customers, suppliers, invoices, purchases, employees, expenses, settings, stockAdjustments, notifications, and timestamp.

17. Q: What does `restoreBackup` expect?
    A: A JSON body with collections (products, customers, etc.) to be restored; it deletes existing docs and inserts provided items.

18. Q: Is `restoreBackup` protected by auth in routes?
    A: As written, `router.post('/restore', restoreBackup)` has no auth protection — it's unprotected by default.

19. Q: Is that a security risk?
    A: Yes; restore should be protected (admin-only) because it can overwrite the database.

20. Q: How is `resetDatabase` protected?
    A: `DELETE /reset` uses `protect` and `authorize('admin', 'Admin')` in `routes/backupRoutes.js`.

21. Q: What is returned by `authController.register`?
    A: JSON with `_id`, `username`, and `role` for the created user.

22. Q: Why is `role` in `User` model an ObjectId?
    A: For normalized role data and to enable shared role documents with permissions.

23. Q: How are default roles initialized?
    A: `initializeDefaultRoles()` is called in `server.js` and likely in `controllers/roleController.js` (not inspected in detail here).

24. Q: What important middleware is mounted in `server.js` for cookies and parsing?
    A: `cookieParser()` and `express.json()`.

25. Q: What does `cors` config in `server.js` allow?
    A: Origins `http://localhost:5173`, `http://localhost:8080`, `https://forbi-pos.vercel.app` with `credentials: true`.

26. Q: Why is `credentials: true` necessary in server CORS config?
    A: It allows the browser to send cookies on cross-origin requests.

27. Q: How should frontend configure fetch to send cookies?
    A: Use `credentials: 'include'` on fetch calls to endpoints that require auth.

28. Q: Where is socket.io configured to accept origins?
    A: In `server.js` when creating `new Server(server, { cors: { origin: [...], credentials: true } })`.

29. Q: How does `notificationService.setSocketIo(io)` relate to routes?
    A: It injects the Socket.IO instance into the notification service to enable real-time pushes.

30. Q: How are controllers and services structured?
    A: Routes call controllers, controllers orchestrate and use services or models, services encapsulate logic (authService, productService, etc.).

31. Q: What pattern is used for authentication in the app?
    A: JWT stored in an HTTP-only cookie, verified on the server for protected routes.

32. Q: How is password hashing handled?
    A: `authService` uses `bcryptjs` to hash and compare passwords.

33. Q: Where is `JWT_SECRET` expected to come from?
    A: From environment variables: `process.env.JWT_SECRET` loaded by `dotenv` in `server.js`.

34. Q: What's the default JWT expiry used?
    A: `expiresIn: '30d'` in `authService.loginUser`.

35. Q: What happens on `authController.logout`?
    A: It clears the `jwt` cookie by setting `res.cookie('jwt', '', { httpOnly: true, expires: new Date(0) })`.

36. Q: How does the frontend track authenticated user state?
    A: It uses `useAuthStore` (likely a Zustand store) to store user info after login.

37. Q: Is the frontend protected pages guarded client-side?
    A: The frontend likely checks `authStore` state and routes to `/login` if no user; server still enforces auth.

38. Q: What should you do if backup download returns 401 after login?
    A: Check that login response set cookie, cookie present in Application tab, and backup request includes `Cookie: jwt=...`.

39. Q: How to debug a 403 from authorize middleware?
    A: Check the response message that contains `User role <value>` to see what the server thinks the role is.

40. Q: If `User role` shows an ObjectId, how to fix it?
    A: Populate `role` in `protect` or compare ObjectId string to expected role ids in `authorize`.

41. Q: Why is `res.json(data)` used for backup instead of `res.download()`?
    A: Simpler route: send JSON, the frontend builds a blob and triggers download; `res.download()` could also be used to send a file.

42. Q: How does the frontend restore backup?
    A: Reads a JSON file, sends it with `POST /api/backup/restore` with `Content-Type: application/json` and `credentials: 'include'`.

43. Q: Why must restore route be protected?
    A: It can delete and insert full collections, which is sensitive and should be admin-only.

44. Q: What are the main database models used in backups?
    A: Product, Customer, Supplier, Invoice, Purchase, Employee, Expense, Settings, StockAdjustment, Notification.

45. Q: What happens to Settings on `resetDatabase`?
    A: Reset intentionally does NOT delete Settings or Users to avoid lockout / config loss.

46. Q: How are roles represented in the `Role` model?
    A: Likely a document with `name` and `permissions` object (inferred from code that checks `role.permissions`).

47. Q: How do frontend components route to backup functions?
    A: Settings page has UI buttons hooking to `handleDownloadBackup`, `handleRestoreClick`, and `handleResetDatabase` functions.

48. Q: What front-end libs are used?
    A: Vite + React + TypeScript, Zustand for store, Sonner for toasts, Lucide for icons, Tailwind for styles.

49. Q: How does login handle role-based redirects?
    A: It checks `data.role === 'admin'` or `data.role?.name === 'Admin'` or `role.permissions` to choose a route.

50. Q: Why is checking both `'admin'` and `role?.name === 'Admin'` needed?
    A: Because `role` can be either a string or an object depending on how it's serialized; code accounts for both forms.

51. Q: How to test backup export with curl using cookie?
    A: First POST login to get `Set-Cookie`, then issue GET with `-H "Cookie: jwt=..."` to `/api/backup/export`.

52. Q: How to inspect JWT contents without verifying secret?
    A: Decode base64 parts (or use `jsonwebtoken.decode(token)`) to view payload including `role`.

53. Q: If `protect` sets `req.user` from DB, why include role in JWT at login?
    A: Token includes role for convenience or stateless checks, but server should still validate current roles against DB where necessary.

54. Q: What are common cookies issues during local development?
    A: `SameSite=Strict`, `Secure` on HTTP, domain mismatch, missing `credentials` on fetch, or CORS misconfiguration.

55. Q: How is CORS configured to allow cookie sending?
    A: `app.use(cors({ origin: [...], credentials: true }))` in `server.js`.

56. Q: If cookie is set but not sent on requests, what to check first?
    A: Check `SameSite` and `Secure` flags and whether `credentials: 'include'` is used on the fetch.

57. Q: What file contains UI for settings and backup?
    A: `ForbiPos-F/src/pages/Settings.tsx`.

58. Q: What content type does restore endpoint expect?
    A: `application/json` in the request body.

59. Q: What happens if restore JSON has invalid schema?
    A: The controller may throw errors on insertMany; the route catches errors and returns `500` with message.

60. Q: How to make restore idempotent?
    A: Use upserts by primary keys or careful merging logic rather than deleteMany + insertMany.

61. Q: What is the risk of deleteMany before insertMany in restore?
    A: If insert fails, data may be lost because previous data was removed; consider transactions or backups.

62. Q: Does `createBackup` include user data?
    A: No — users are intentionally excluded from the backup payload in the current implementation.

63. Q: Why might users be excluded from backups?
    A: To avoid storing sensitive credentials or to prevent lockouts on restore; but user export/import can be added if needed.

64. Q: How are notifications stored and backed up?
    A: Notifications come from `Notification` model and are included in backup's `notifications` array.

65. Q: How are stock adjustments handled in backups?
    A: `stockAdjustments` are included as an array in the backup JSON.

66. Q: How to safely test restore locally?
    A: Make a backup, copy it to a safe location, then test restore on a local DB backup clone.

67. Q: How does the frontend present backup success/failure?
    A: Using Sonner toasts: `toast.success` or `toast.error` with description messages.

68. Q: What HTTP method is used for backup export?
    A: `GET /api/backup/export`.

69. Q: What HTTP method is used for restore?
    A: `POST /api/backup/restore`.

70. Q: Why use `credentials: 'include'` only for auth endpoints and not static assets?
    A: Credentials are required when endpoints rely on cookies; static assets don't need auth cookies.

71. Q: How to ensure secure cookies in production?
    A: Use `secure: true` and `sameSite: 'none'` with HTTPS when frontend and backend are cross-site.

72. Q: How do role permissions influence route visibility on frontend?
    A: Frontend reads `role.permissions` and shows/hides UI elements and navigation links accordingly.

73. Q: What happens if you change `JWT_SECRET` while tokens are active?
    A: Existing tokens will fail verification and users will be forced to re-login.

74. Q: How to force token rotation without logging users out immediately?
    A: Use short-lived access tokens and refresh tokens; rotate secrets gradually with revocation lists.

75. Q: What is the purpose of `initializeDefaultRoles()` in `server.js`?
    A: To ensure default role documents exist in the DB at startup (e.g. Admin, User, etc.).

76. Q: How would you add API rate limiting for backup endpoints?
    A: Add middleware like `express-rate-limit` to throttle repeated requests, especially for destructive endpoints.

77. Q: How can backup size be reduced before download?
    A: Strip unused fields, compress JSON, or allow selecting collections to export.

78. Q: What CLI commands to run frontend and backend locally?
    A: Backend typically `npm install` then `npm run dev` or `node server.js`; frontend `npm install` then `npm run dev` (Vite).

79. Q: How to verify that `User` role is populated after login token is set?
    A: Inspect decoded JWT payload or console.log `user.role` before setting token in `authService.loginUser`.

80. Q: If `authorize` expects string role names, how to adapt it to ObjectId roles?
    A: Either populate role to get `role.name`, or compare `req.user.role.toString()` to known role ids.

81. Q: How are errors logged in controllers?
    A: Controllers catch errors and use `console.error` and `res.status(500).json({ message: ... })`.

82. Q: Where to add request logging middleware?
    A: Add a middleware (e.g., `morgan`) in `server.js` before routes to log incoming requests.

83. Q: How can you protect the restore endpoint quickly without deep refactor?
    A: Add `protect` and `authorize('admin', 'Admin')` to the `/restore` route in `routes/backupRoutes.js`.

84. Q: What data consistency concerns exist when restoring backups?
    A: Referential integrity, duplicate keys, and relationships relying on ObjectIds might break if referenced ids change.

85. Q: How to handle ObjectId collisions on restore between different databases?
    A: Map ids, use natural keys, or import data into a clean environment using ETL scripts to reassign ids.

86. Q: Does the frontend use environment variables for API base URL?
    A: Yes — `API_BASE_URL` comes from `ForbiPos-F/src/utils/apiConfig`.

87. Q: How to extend backup to include user data safely?
    A: Export sanitized user objects without passwords or use a separate admin-only user export with careful access controls.

88. Q: How to handle large backup responses in the browser?
    A: Stream download, paginate export, or let server create file and return a download URL instead of giant JSON in-memory.

89. Q: Why might `fetch(...).json()` fail on backup response?
    A: If response isn't JSON (e.g., server returned a text error), or response body is too large, or network error.

90. Q: How to trigger backup download in a mobile browser reliably?
    A: Use server-generated file with an accessible URL and link that opens in a browser tab; blob downloads can be unreliable on mobile.

91. Q: How to schedule automated backups on the server side?
    A: Use cron jobs or implement a scheduled task (node-cron) to write backup files to disk or cloud storage.

92. Q: How to encrypt backups before storing or downloading?
    A: Use symmetric encryption (AES) on exported JSON or use transport-level TLS and storage encryption at rest.

93. Q: Where are API routes organized in the backend?
    A: Under the `routes/` directory, one file per resource (authRoutes, backupRoutes, productRoutes, etc.).

94. Q: What's the typical controller responsibility?
    A: Validate request, call services or models, handle errors, and return responses.

95. Q: How can you add request validation to backup restore?
    A: Use a JSON schema validator (AJV) or express-validator middleware to validate incoming backup structure before restore.

96. Q: How to prevent CSRF when using cookies for auth?
    A: Use sameSite cookies, CSRF tokens, or switch to token-in-header flows (Authorization header) for APIs.

97. Q: What effect does `httpOnly: true` have on the `jwt` cookie?
    A: It prevents JavaScript from accessing the cookie via `document.cookie`, mitigating XSS risk.

98. Q: If you switch to Authorization header with Bearer token, what changes in frontend?
    A: Frontend must store token (e.g., in memory or localStorage) and set `Authorization: Bearer <token>` on requests; cookies no longer required.

99. Q: Why might using localStorage for JWT be riskier than httpOnly cookie?
    A: localStorage is accessible to JavaScript and vulnerable to XSS attacks; httpOnly cookies are not.

100. Q: How to inspect the role permissions in the frontend after login?
     A: Check `data.role` returned by login and inspect `data.role.permissions` if present.

101. Q: Why is `role` sometimes a string and sometimes an object in frontend code?
     A: Because server may serialize it differently depending on whether role was populated or stored as an id.

102. Q: How to make role format consistent across API responses?
     A: Always populate role on user find operations and return a normalized structure from controllers.

103. Q: What happens if `User.findById(decoded.id)` returns null in `protect`?
     A: The middleware should treat this as unauthorized; current code would set `req.user` to null and likely throw later; better to return 401.

104. Q: How to make error messages more useful for debugging auth issues?
     A: Log verification errors, include specific messages in server logs (not in client responses), and return standardized error codes and minimal messages to client.

105. Q: How should the frontend handle a 401 response globally?
     A: Intercept 401 in a fetch wrapper or interceptor, clear auth state, redirect to login, and show a message.

106. Q: How to implement a fetch wrapper that adds `credentials: 'include'` automatically?
     A: Create a helper function for API calls that merges default options: `{ credentials: 'include', headers: {...} }`.

107. Q: Where to restrict role-based UI in the frontend?
     A: In components and routes — check `authStore` role and `permissions` before rendering sensitive UI.

108. Q: How to unit test `authorize` middleware?
     A: Mock `req.user` with roles and call middleware functions, asserting `next()` invoked or response status set.

109. Q: How to integration test backup endpoints?
     A: Use a test database, seed data, call `/api/backup/export` and `/api/backup/restore`, verify DB state post-restore.

110. Q: How to protect API keys and secrets in production?
     A: Use environment variables, secret managers, and never commit them to source control.

111. Q: How do controllers handle async errors currently?
     A: They use try/catch within async functions and return `res.status(500)` on errors.

112. Q: How to add global error handling middleware?
     A: Add an Express error-handling middleware `app.use((err, req, res, next) => { ... })` to centralize logging and responses.

113. Q: How to safely allow restore from a file in the UI?
     A: Confirm the user is admin, show confirmation dialog, validate file contents, and perform restore in a transaction if supported.

114. Q: Why might `insertMany` fail on restore?
     A: Duplicate keys, missing required fields, or schema mismatches.

115. Q: How to add transactional restore with MongoDB?
     A: Use sessions and `session.startTransaction()` with `insertMany` operations then `session.commitTransaction()`.

116. Q: Why exclude Users from `resetDatabase`?
     A: To prevent admin lockout; resetting users could remove all admin accounts.

117. Q: How to implement soft deletes for safety?
     A: Add a `deleted` flag and filter queries instead of physically deleting documents.

118. Q: What is the recommended content type for backup downloads?
     A: `application/json` with `.json` filename or `application/gzip` if compressed.

119. Q: How to compress backup before download on server?
     A: Use zlib to gzip JSON and return as `application/gzip` or `application/octet-stream`.

120. Q: How to secure reset endpoint in addition to auth?
     A: Add confirmation steps, rate-limiting, IP allowlists, and require multiple admin approvals.

121. Q: How does the frontend restore UI handle file input change?
     A: Reads file via `FileReader`, parses JSON, and posts to `/api/backup/restore`.

122. Q: How to add progress indicator for large restores?
     A: Use server-side status tracking (jobs) and poll status via WebSocket or periodic fetches.

123. Q: What are common reasons fetch returns a network error during backup?
     A: CORS misconfiguration, server not reachable, large payload causing timeouts, or SSL issues in production.

124. Q: How to make backup endpoint return a downloadable URL instead of JSON body?
     A: Generate backup file on server, store in temp storage, and return a signed URL for download.

125. Q: How to avoid blocking the event loop with large DB operations?
     A: Use streams, chunked inserts, or offload heavy operations to worker processes.

126. Q: Why is `cookieParser()` necessary?
     A: It populates `req.cookies` so middleware can access the `jwt` cookie.

127. Q: What could cause `req.cookies.jwt` to be undefined despite cookie present in browser?
     A: Cookie domain/path mismatch, cookie blocked by browser due to SameSite/Secure, or missing `credentials` on request.

128. Q: How to verify cookie path/domain settings?
     A: Inspect `Set-Cookie` header attributes in the login response.

129. Q: What are best practices for storing backups long-term?
     A: Encrypt, store in object storage (S3), retain versions, and set retention policies.

130. Q: How to roll back a failed restore?
     A: Use DB transactions or keep a snapshot/backup before restore to re-import if needed.

131. Q: How to add audit logs for backup and restore actions?
     A: Log user id, timestamp, ip, and action to a persistent audit collection or external logging system.

132. Q: How to prevent accidental restores from malformed files?
     A: Validate schema, require checksum/signature verification, and require confirmation.

133. Q: Should backup include indexes?
     A: Indexes are part of DB schema; you can export index definitions separately or recreate them on restore.

134. Q: How to test CORS cookie behavior across environments?
     A: Run frontend and backend on different ports and test `SameSite` and `secure` cookie settings in dev tools.

135. Q: How to handle multiple frontend origins in CORS config?
     A: Include all allowed origins in `cors({ origin: [ ... ] })` or compute dynamically from an allowlist.

136. Q: How to inspect server logs for token verification errors?
     A: Look for `jwt.verify` catch logs or add supplemental logging in `protect` middleware.

137. Q: How to invalidate a JWT before expiry?
     A: Use token revocation lists (stored in DB or cache) checked during `protect` or implement short expirations with refresh tokens.

138. Q: Why use HTTP-only cookie over Authorization header in some cases?
     A: Simplicity and protection from XSS (cookie can't be accessed by JavaScript), but cookies are vulnerable to CSRF.

139. Q: How to mitigate CSRF if using cookies?
     A: Use sameSite cookies, CSRF tokens for state-changing endpoints, or require additional headers that are not sent cross-site.

140. Q: Where are settings saved on the backend?
     A: In the `Settings` model; controllers use `Settings` to read and update values.

141. Q: How to add validation for settings updates?
     A: Validate `formData` shape in the settings controller using a schema or express-validator.

142. Q: How to avoid sending full user role object over the network?
     A: Return only needed fields (name and permissions) or specific permissions array.

143. Q: How to handle permissions for fine-grained UI control?
     A: Store permission keys (e.g., `{ invoices: true }`) and check them when rendering components.

144. Q: Why might role-based redirect logic in login fail?
     A: Because `role` value may be inconsistent (id vs name vs object), so checks need normalization.

145. Q: How to normalize role in login response?
     A: In `authController.login`, return `role: user.role.name || user.role` after populating role.

146. Q: How to secure the JWT against tampering?
     A: Use a strong `JWT_SECRET`, rotate secrets carefully, and use appropriate algorithms (HS256/RS256).

147. Q: How to support multiple auth methods (cookies + header)?
     A: Accept either cookie JWT or `Authorization` header in `protect` middleware and verify whichever is present.

148. Q: How to limit backup access in multi-tenant environment?
     A: Include tenant id in token and in backup payload, and check tenant scope on backup/restore.

149. Q: How to run database backups without downtime?
     A: Use DB-native snapshot tools, logical dumps, or streaming backups; avoid operations that lock collections.

150. Q: Why is `insertMany(items)` used rather than `create` per item?
     A: `insertMany` is more efficient for bulk inserts.

151. Q: How to catch duplicate key errors gracefully on restore?
     A: Catch specific error codes (`E11000`) and handle conflicts by skipping or renaming.

152. Q: How to ensure exported backup JSON has stable references?
     A: Export using natural keys or export id mapping so relationships can be restored reliably.

153. Q: How to add role management UI?
     A: Create a Roles page that lists roles, shows permissions, and allows CRUD operations using role APIs.

154. Q: How to test authorization middleware manually?
     A: Create a test user with admin role, login to get cookie, perform protected request with cookie, observe result.

155. Q: How to store file-based backups on server with automatic pruning?
     A: Write backups to a directory and run a retention policy to remove backups older than X days.

156. Q: How to add versioning to backup files?
     A: Include timestamp and optionally commit hash or schema version in the filename or metadata.

157. Q: How to ensure backup consistency across collections?
     A: Use DB transactions when possible or stop writes during backup (quiesce) to get a consistent snapshot.

158. Q: How to handle large files during restore in HTTP?
     A: Increase body size limit in Express with `express.json({ limit: '50mb' })` or upload files and stream them server-side.

159. Q: Where to set body parser limits in backend?
     A: `app.use(express.json({ limit: '...' }))` in `server.js`.

160. Q: How to give user feedback if restore fails partially?
     A: Return detailed status including which collection failed and why and log full error server-side.

161. Q: How to avoid exposing internal errors to clients?
     A: Return generic error messages and log detailed errors on server with secure access.

162. Q: How to handle multi-environment API base URLs in frontend?
     A: Use environment variables in Vite (.env) and expose `API_BASE_URL` via `import.meta.env`.

163. Q: How to implement role-based access for API endpoints?
     A: Use `authorize(...roles)` middleware on routes to restrict access to allowed roles.

164. Q: How to ensure role names are case-insensitive?
     A: Normalize role names to lowercase when saving and comparing, or use canonical constants.

165. Q: How to add an endpoint to check current user (`/api/auth/me`)?
     A: Create a protected route that returns `req.user` (without password) for frontend to validate session.

166. Q: How to handle CSRF when using sameSite cookies and cross-site requests?
     A: SameSite mitigates CSRF for many cases, but for full protection use CSRF tokens on state-changing operations.

167. Q: How to centralize fetch error handling in frontend?
     A: Build an `apiClient` wrapper that handles status codes, retries, token refresh, and shows toasts.

168. Q: What to do if login returns 200 but cookie not set?
     A: Inspect `Set-Cookie` header attributes; adjust `credentials` on fetch, `sameSite` or `secure` flags, and CORS.

169. Q: How to store permissions on roles in DB?
     A: Use a `permissions` object or array (e.g., `{ invoices: true, products: true }`) and index when needed.

170. Q: How to add audit trail for admin restore/reset actions?
     A: Save a record with admin id, timestamp, pre/pos snapshot pointers, and change summary.

171. Q: How to protect backup download endpoints from unauthorized scraping?
     A: Require auth, rate-limit, and optionally add user-agent or IP checks for sensitive endpoints.

172. Q: How to check whether login cookies are blocked by browser extensions?
     A: Test in incognito without extensions or different browser to isolate extension interference.

173. Q: How to troubleshoot cross-origin cookie issues on Chrome?
     A: Use DevTools to inspect `Set-Cookie` header and look for warnings about `SameSite` or `Secure` flags.

174. Q: How to implement role check middleware that supports both object and string roles?
     A: Normalize by checking `typeof req.user.role === 'object' ? req.user.role.name : req.user.role`.

175. Q: How to ensure `protect` returns early on missing user?
     A: After `findById`, if no user found call `return res.status(401).json({ message: 'Not authorized' })`.

176. Q: How to log IP address for admin actions?
     A: Read `req.ip` or `req.headers['x-forwarded-for']` and save it with audit logs.

177. Q: How to add multi-factor authentication (MFA)?
     A: Add an opt-in MFA step with TOTP or SMS and record MFA state in user's profile.

178. Q: How to rotate `JWT_SECRET` safely?
     A: Introduce key ids (kid), sign with new key while accepting tokens signed by old keys for a transition period, then revoke old keys.

179. Q: How to implement incremental backups?
     A: Track changes since last backup using timestamps and export deltas instead of full DB.

180. Q: How to secure backup downloads in cloud deployments?
     A: Use signed URLs, short-lived tokens, and restrict downloads to authenticated requests.

181. Q: How to handle file uploads (restore) securely?
     A: Validate file type/size, parse safely, and run restore in a sandbox or worker process with limited privileges.

182. Q: How to implement role-based API documentation access?
     A: Serve API docs at protected route and restrict access to admin roles.

183. Q: What is a minimal test to confirm backend `protect` works?
     A: Set a valid `jwt` cookie and request a protected endpoint; expect 200 for valid token and 401 for invalid/missing.

184. Q: Where to configure allowed origins for CORS when deploying?
     A: Configure `server.js` CORS origin list from environment variables pointing to frontend URLs.

185. Q: How to handle backward compatibility for role schema changes?
     A: Support older token formats during transition and migrate DB roles carefully.

186. Q: How to implement per-user backup permissions (beyond admin)?
     A: Add a specific permission flag like `canBackup` in role permissions and check it in `authorize`.

187. Q: How to centralize role name constants?
     A: Create a `roles.js` with constants like `ROLE_ADMIN = 'admin'` and import/use throughout backend and frontend.

188. Q: How to test restore on CI safely?
     A: Use ephemeral test DB instances and clean state before/after tests.

189. Q: How to ensure readable error messages on frontend without leaking internals?
     A: Map server error codes to user-friendly messages while logging details server-side.

190. Q: How to run database migrations before restore if schema changed?
     A: Maintain migration scripts and run migration tool prior to applying restored data.

191. Q: How to add expiry metadata to backup payload?
     A: Include `timestamp` in backup and optionally `schemaVersion` and TTL info in metadata.

192. Q: How to check if backup route accidentally left unprotected?
     A: Inspect `routes/backupRoutes.js` for missing `protect`/`authorize` and test endpoints unauthenticated.

193. Q: How to add a dry-run mode for restore?
     A: Add an optional flag `dryRun=true` to validate transforms but not commit DB changes.

194. Q: How to safely expose backup endpoints in production?
     A: Use admin-only roles, require multi-factor, and log/audit downloads and restores.

195. Q: How to reduce blast radius of an accidental reset?
     A: Require confirmation via UI, confirmation codes, or an out-of-band approval flow.

196. Q: How to ensure front and back timezones don't break timestamps in backups?
     A: Store timestamps in ISO UTC and normalize on restore.

197. Q: How to monitor backup size growth over time?
     A: Log backup sizes and keep retention metrics; alert when size grows unexpectedly.

198. Q: How to design API endpoints to be idempotent during restore?
     A: Use idempotent operations or include a unique request id to avoid reapplying the same restore twice.

199. Q: How to handle partial permission updates to a role?
     A: Only update changed permission keys and keep backward-compatible defaults for missing keys.

200. Q: How to test role-based UI comprehensively?
     A: Create test users per role, run automated UI tests to ensure page access and button visibility match permissions.

201. Q: What should you do if backup export works locally but fails in production with 401?
     A: Check cookie `secure` flag, domain, and CORS config; ensure production frontend and backend origins match cookie settings.

202. Q: How to log successful and failed login attempts securely?
     A: Log timestamp, ip, username (not password), and result; consider account lockout on repeated failures.

203. Q: How to implement permission inheritance between roles?
     A: Allow roles to reference parent roles or compute effective permissions by merging role permissions.

204. Q: How to add a confirmation step in frontend for reset operations?
     A: Show an `AlertDialog` with explicit confirmation and an extra checkbox or input before calling reset.

205. Q: How to add user-friendly labels to permissions in UI?
     A: Map permission keys to readable labels in a central config file used by the Roles UI.

206. Q: How to ensure the backup download filename is meaningful?
     A: Include timestamp and maybe environment in filename: `backup-YYYY-MM-DD-env.json`.

207. Q: How to handle non-admin users requesting backup route accidentally?
     A: `authorize` will return 403; frontend should hide the backup UI from users without permission.

208. Q: How to instrument performance of backup endpoints?
     A: Measure execution time, memory usage, and DB query counts; add telemetry/tracing.

209. Q: How to handle migration of role permissions structure?
     A: Write migration scripts to map old permission keys to new structure and maintain compatibility in code.

210. Q: How to gracefully stop long-running restore operations?
     A: Track restore jobs with cancellable worker tasks controlled by an admin endpoint.

211. Q: How to configure log level differently for prod and dev?
     A: Use environment variable `LOG_LEVEL` and configure logger (winston or pino) accordingly.

212. Q: How to add per-collection selective backups in UI?
     A: Add checkboxes for collections in Settings -> Backup and pass selection to an export endpoint.

213. Q: How to avoid exposing passwords in backups?
     A: Exclude `User.password` from export or store hashes only and consider not exporting users.

214. Q: How to validate restore JSON structure before database operations?
     A: Use a schema validator (AJV) to assert expected keys and types before delete/insert operations.

215. Q: How to test socket notification integration locally?
     A: Run backend and frontend, login a user, open socket in client, trigger notifications and observe real-time updates.

216. Q: How to implement multi-tenant backup isolation?
     A: Include tenant id in each document and enforce tenant-scoped queries and exports.

217. Q: How to protect backup/restore endpoints with API keys in addition to auth?
     A: Require an admin-level API key header checked server-side for critical endpoints.

218. Q: How to keep backups compatible across application versions?
     A: Store `schemaVersion` in backup and create migration tools to upgrade/downgrade backup payloads.

219. Q: How to add a dry-run preview of restore changes in UI?
     A: Implement a server `/api/backup/preview-restore` that validates and returns a summary of changes without applying them.

220. Q: What immediate steps should you take if backup download still returns Unauthorized after adding `credentials: 'include'`?
     A: Run the diagnostic checklist: confirm `Set-Cookie` in login response, cookie present under Application, cookie sent in backup request, check `SameSite/Secure`, and inspect server response body for 401 vs 403 to determine next fix.

---

Next steps: commit `q_a.md` into frontend repo, or tell me if you want this file moved/renamed or formatted differently.
