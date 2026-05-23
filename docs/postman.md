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
- `accessToken`: saved automatically after `/login`, `/login/refresh`, and `/login/refresh/cookie`
- `accountId`: saved automatically after `/register/verify`
- `username`: saved automatically after `/register/verify`

## Recommended Flow

1. `Healthz`
2. `Register`
3. Fill in `otpCode` after receiving the OTP
4. `Verify Register`
5. `Login`
6. `Refresh Token`
7. `Refresh Token From Cookie`
8. `JWKS`

## Notes

- The `Register` request stores `ticketId` into the active Postman environment.
- The `Login` and `Refresh Token` requests store both `accessToken` and `refreshToken`.
- The `Refresh Token From Cookie` request depends on Postman's cookie jar receiving the `ddone_refresh_token` cookie from a previous login or refresh response.
- `JWKS` is public and does not require authentication.
