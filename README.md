# Mutual TLS Certificate-Bound Access Tokens

This package is a implementation of Certificate-Bound Access Tokens written in [OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens draft-ietf-oauth-mtls-14](https://tools.ietf.org/html/draft-ietf-oauth-mtls-14).

### Purpose

This package's responsibility is creating and verifing Certificate-Bound token.

This token is used for Access Token and Refresh Token of OAuth 2.0.

How to pass the token to resource server? How to mangae key pair and certificate? There are out of scope.

### How it works

![image](https://user-images.githubusercontent.com/1120995/66738957-a022d880-eeaa-11e9-8d39-339a11d667d9.png)

The OAuth 2.0 back channel process is below.

+ 1. Client server sends the request to token endpoint of Authorization server.
+ 2. Authorization server create token and return it if the Client server pass a authentication.
+ 3. Clinet server request to Resource server with the token.
+ 4. Resource server verify the token and returns data if the token is valid.

The problem of Bearer token is that attcker gets the access token, they can access to the Resource server. Mutual TLS Certificate-Bound Access Tokens defined in [OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens draft-ietf-oauth-mtls-14](https://tools.ietf.org/html/draft-ietf-oauth-mtls-14) is a method how to verify the proof of possession. The summary of this method is below.

+ Basiclly, Client server, Authorization server and Resource server must be connected by mutual TLS.
+ When Authorization server creates access token, the thumbprint of certificate is added to the token. The certificate is the client certificate used in mTLS between Client server and Authorization server.
+ When Resource server gets the token, the thumbprint written in the token is compared with the thumbprint of certificate which is used in mTLS connection between Client server and Resource server.
+ If attcker who gets the access token try to gets a resource from Resource server, they have to connect mTLS as Client server. But they couldn't do it because they don't have the private key which uses Client server.


### How to use
+ Define token format. It is defined in authorization server.
  ```
  // default token
  token := auth.Token{
    Iss: "some organization",
  }

  // token with custom fields
  type customToken struct {
    auth.Token
    ClientID string   `json:"client_id"`
    Email    string   `json:"email"`
    Array    []string `json:"array"`
  }
  token := customToken{
    Token: auth.Token{
      Iss: "kokukuma",
    },
    ClientID: "3",
    DNSName:  "kokukuma.com",
    Test:     []string{"kokuban", "kumasan"},
  }
  ```

+ Encode token to signedJWT. It is done in authorization server.
  ```
  tokenStr, err := auth_grpc.IssueToken(ctx, privKey, token)
  ```

+ Decode and verify the signedJWT. It is done in resource server.
  ```
	token := &customToken{}
	err = auth_grpc.DecodeToken(ctx, tokenStr, pubKey, token)
  ```

