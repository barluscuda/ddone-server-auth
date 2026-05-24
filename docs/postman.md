# Postman Guide

This repository includes Postman assets for the current auth API in [postman/ddone-server-auth.postman_collection.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.postman_collection.json) and [postman/ddone-server-auth.local.postman_environment.json](/home/mrbarlus/coding/DDONE/ddone-server-auth/postman/ddone-server-auth.local.postman_environment.json).

## Import

1. Import the collection file.
2. Import the local environment template.
3. Select the imported environment before sending requests.

## Environment Variables

- `baseUrl`: default `http://localhost:3000`
- `phoneNumber`: phone number used for registration and login
- `password`: password used for registration and login
- `otpCode`: OTP value for `/registrations/verify`
- `ticketId`: saved automatically after `/registrations`
- `resetOtpCode`: OTP value for `/password-resets/verify`
- `resetTicketId`: saved automatically after `/password-resets`
- `refreshToken`: saved automatically after `/tokens` and `/tokens/refresh`
- `accessToken`: saved automatically after `/tokens`, `/tokens/refresh`, and `/sessions/token`
- `accountId`: saved automatically after `/registrations/verify`
- `username`: saved automatically after `/registrations/verify`
- `currentPassword`: current password used for `/settings/password`
- `newPassword`: replacement password used for password reset and change-password flows
- `newUsername`: replacement username used for `/settings/username`

## Recommended Flow

1. `Healthz`
2. `Register`
3. Fill in `otpCode` after receiving the OTP
4. `Verify Register`
5. `Login`
6. `Refresh Token`
7. `Create Login Session`
8. `Session Access Token`
9. `Forgot Password`
10. Fill in `resetOtpCode` after receiving the reset OTP
11. `Verify Forgot Password`
12. `Login`
13. `Change Password`
14. `Settings`
15. `Update Username`
16. `Token Manager`
17. `Revoke Token`
18. `Revoke All Tokens`
19. `Sessions`
20. `Current Session`
21. `Revoke Session`
22. `Revoke Other Sessions`
23. `Revoke All Sessions`
24. `JWKS`

## Notes

- The `Register` request stores `ticketId` into the active Postman environment.
- The `Forgot Password` request stores `resetTicketId` into the active Postman environment.
- The `Login` and `Refresh Token` requests are body-token flows and store both `accessToken` and `refreshToken`.
- The `Verify Forgot Password` and `Change Password` requests update the `password` environment variable to match `newPassword` after a successful change.
- The `Create Login Session` request relies on Postman's cookie jar receiving the `ddone_session` cookie; the JWT stays in server-side session state.
- The `Session Access Token` request depends on that cookie jar entry and returns the currently active access token for the session, or a fresh one if the stored token has already expired.
- The `Settings`, `Update Username`, token-manager requests, session-control requests, and `Change Password` requests require `accessToken` and send it in the `Authorization` header.
- The `Settings` request uses `GET /settings/me`; `GET /settings` is also available.
- Token manager endpoints live under `/tokens`, including `GET /tokens`, `DELETE /tokens/:tokenId`, and `POST /tokens/revoke-all`.
- Session control endpoints live under `/sessions`, including `GET /sessions`, `GET /sessions/current`, `DELETE /sessions/:sessionId`, `POST /sessions/revoke-others`, and `POST /sessions/revoke-all`.
- `JWKS` is public and does not require authentication.
