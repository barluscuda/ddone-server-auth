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
- `otpCode`: OTP value for `/register/verify`
- `ticketId`: saved automatically after `/register`
- `refreshToken`: saved automatically after `/login` and `/login/refresh`
- `accessToken`: saved automatically after `/login`, `/login/refresh`, and `/login/session/token`
- `accountId`: saved automatically after `/register/verify`
- `username`: saved automatically after `/register/verify`

## Recommended Flow

1. `Healthz`
2. `Register`
3. Fill in `otpCode` after receiving the OTP
4. `Verify Register`
5. `Login`
6. `Refresh Token`
7. `Create Login Session`
8. `Session Access Token`
9. `Account Me`
10. `Account Sessions`
11. `JWKS`

## Notes

- The `Register` request stores `ticketId` into the active Postman environment.
- The `Login` and `Refresh Token` requests are body-token flows and store both `accessToken` and `refreshToken`.
- The `Create Login Session` request relies on Postman's cookie jar receiving the `ddone_session` cookie; the JWT stays in server-side session state.
- The `Session Access Token` request depends on that cookie jar entry and returns the currently active access token for the session, or a fresh one if the stored token has already expired.
- The `Account Me` and `Account Sessions` requests require `accessToken` and send it in the `Authorization` header.
- `JWKS` is public and does not require authentication.
