---
title: "OAuth 2.0 Bearer Token Usage for Authorization"
description: "An introduction into utilizing the Authelia OpenID Connect 1.0 Provider as an authorization method for resources protected by a proxy"
lead: "An introduction into utilizing the Authelia OpenID Connect 1.0 Provider as an authorization method for resources protected by a proxy."
date: 2023-11-28T16:24:21+11:00
draft: false
images: []
menu:
  integration:
    parent: "openid-connect"
weight: 611
toc: true
---

Access Tokens can be granted which are used as an authorization mechanism for resources protected by the forwarded
authorization flow which directly integrates into proxies.

## General Protections

The following protections have been taken into account:

- The Access Tokens which are used for this purpose must have been granted the correct `authelia.authz.bearer` scope.
- The user who grants consent for the token is effectively the user who is considered for the authorization rule
  processing.
- The audience of the token is also considered and if the token does not have an audience which is an exact match or the
  prefix of the URL being requested the authorization will automatically be denied.
- At this time each request using this scheme will cause a lookup to be performed on the authentication backend.

For example if `john` consents to grant the token and it includes the audience `https://app.example.com` but the user
`john` is not normally authorized to visit `https://app.example.com` the token will not grant access to this resource.
In addition if `john` has his access updated via the acess control rules, their groups, etc. then this access is
automatically applied to these tokens.

These rules effectively give both administrators and end-users fine-grained control over which endpoints can utilize
this authorization scheme as administrators will be required to allow each individual URL prefix which can be requested
and end users will be able to request individual audiences from the allowed list (effectively narrowing the audience
of the token).

The following recommendations should be considered by users who use this authorization method:

- Using the JWT Profile for Access Tokens effectively makes the introspection stateless and is discouraged for this
  purpose unless you have specific performance issues. We would rather find the cause of the performance issues and
  improve them in an instance where they are noticed.

## Authorization Endpoint Configuration

This authorization scheme is not available by default and must be explicitly enabled. The following examples demonstrate
how to enable this scheme (along with the basic scheme). See the
[Server Authz Endpoints](../../configuration/miscellaneous/server-endpoints-authz.md) configuration guide for more
information.

```yaml
server:
  endpoints:
    authz:
      forward-auth:
        implementation: 'ForwardAuth'
        authn_strategies:
          - name: 'HeaderProxyAuthorization'
            schemes:
              - 'Basic'
              - 'Bearer'
          - name: 'CookieSession'
      ext-authz:
        implementation: 'ExtAuthz'
        authn_strategies:
          - name: 'HeaderProxyAuthorization'
            schemes:
              - 'Basic'
              - 'Bearer'
          - name: 'CookieSession'
      auth-request:
        implementation: 'AuthRequest'
        authn_strategies:
          - name: 'HeaderAuthRequestProxyAuthorization'
            schemes:
              - 'Basic'
              - 'Bearer'
          - name: 'CookieSession'
      legacy:
        implementation: 'Legacy'
        authn_strategies:
          - name: 'HeaderLegacy'
          - name: 'CookieSession'
```

## Client Restrictions

In addition to the above protections, this scope **_MUST_** only be configured on clients with strict security rules
which are:

1. Are not configured with any additional scope with the following exceptions:
   - The `offline_access` scope.
2. Have both PAR and PKCE with the `S256` challenge enforced.
3. Have a list of audiences which represent the resources permitted to be allowed by generated tokens.
4. Have the `explicit` consent mode.
5. Only allows the `authorization_code` and `refresh_token` grant types.
6. Only allows the `code` response type.
7. Only allows the `form_post` response mode.
8. Must either:
  - Be a public client with the Token Endpoint authentication method `none`. See configuration option
    `token_endpoint_auth_method`.
  - Be a confidential client with a secret and the Token Endpoint authentication method `client_secret_basic` or
    `client_secret_post`. See configuration option `token_endpoint_auth_method`.

### Examples

The following examples illustrate how the [Client Restrictions](#client-restrictions) should be applied to a client.

#### Public Client Example

```yaml
identity_providers:
  oidc:
    clients:
      - id: 'example-one'
        public: true
        redirect_uris:
          - 'http://localhost:2121'
        scopes:
          - 'offline_access'
          - 'authelia.authz.bearer'
        audience:
          - 'https://app.example.com'
          - 'https://app2.example.com'
        grant_types:
          - 'authorization_code'
          - 'refresh_token'
        response_types:
          - 'code'
        response_modes:
          - 'form_post'
        consent_mode: 'explicit'
        enforce_par: true
        enforce_pkce: true
        pkce_challenge_method: 'S256'
        token_endpoint_auth_method: 'none'
```

#### Confidential Client Example

```yaml
identity_providers:
  oidc:
    clients:
      - id: 'example-two'
        secret: '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2CJPOsKaPK0hjf.9yHxzQGZziziccp6Yng'  # The digest of 'insecure_secret'.
        public: false
        redirect_uris:
          - 'https://id.example.com'
        scopes:
          - 'offline_access'
          - 'authelia.authz.bearer'
        audience:
          - 'https://app.example.com'
          - 'https://app2.example.com'
        grant_types:
          - 'authorization_code'
          - 'refresh_token'
        response_types:
          - 'code'
        response_modes:
          - 'form_post'
        consent_mode: 'explicit'
        enforce_par: true
        enforce_pkce: true
        pkce_challenge_method: 'S256'
        token_endpoint_auth_method: 'client_secret_post'
```
