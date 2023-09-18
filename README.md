[![Build Status](https://travis-ci.org/pierre-vigier/dancer2-plugin-oauth2-server.svg?branch=master)](https://travis-ci.org/pierre-vigier/dancer2-plugin-oauth2-server)

# NAME

Dancer2::Plugin::OAuth2::Server - Easier implementation of an OAuth2 Authorization
Server / Resource Server with Dancer2
Port of Mojolicious implementation : https://github.com/Humanstate/mojolicious-plugin-oauth2-server

# SYNOPSIS

    use Dancer2::Plugin::OAuth2::Server;

    To protect a route, declare it like following:

    get '/protected' => oauth_scopes 'desired_scope' => sub { ... }

# DESCRIPTION

Dancer2::Plugin::OAuth2::Server is a port of Mojolicious plugin for OAuth2 server
With this plugin, you can implement an OAuth2 Authorization server and Resource server without too much hassle.
The Basic flows are implemented, authorization code, access token, refresh token, ...

A "simple" implementation is provided with a "in memory" session management, however, it will not work on multi process persistent
environment, as each restart will loose all the access/refrest tokens. Token will also not be shared between processes.

For a usable implementation in a realistic context, you will need to create a class implementing the Role Dancer2::Plugin::OAuth2::Server::Role,
and configure the server\_class option in configuration of the plugin. The following methods needs to be implemented:

        login_resource_owner
        confirm_by_resource_owner
        verify_client
        store_auth_code
        generate_token
        verify_auth_code
        store_access_token
        verify_access_token

On the resource server side, to protect a resource, just use the dsl keyword oauth\_scopes with
either one scope or the list of scope needed. In case the authorization header provided is not correct,
a 400 http code is returned with an erro message.
If the Authorization header is correct and the access is granted, the access token information are
stored within the var keyword, in oauth\_access\_token, for the time of the request. You can access the
access token information through var('oauth\_access\_token') within the route code itself.

# CONFIGURATION

## authorize\_route

The route that the Client calls to get an authorization code. Defaults to /oauth/authorize
The route is accessible through http GET method

## access\_token\_route

The route the the Client calls to get an access token. Defaults to/oauth/access\_token
The route is accessible through http POST method

## auth\_code\_ttl

The validity period of the generated authorization code in seconds. Defaults to
600 seconds (10 minutes)

## access\_token\_ttl

The validity period of the generated access token in seconds. Defaults to 3600
seconds (1 hour)

## clients

list of clients for the simple default implementation

    clients:
      client1:
        client_secret: secret
        scopes:
          identity: 1
          other: 0
      client2:
        client_secret: secret2
        scopes:
          identity: 1
          other: 1
        redirect_uri:
          - url1
          - url2

Note the clients config is not required if you add the verify\_client callback,
but is necessary for running the plugin in its simplest form (when no server class
is provided). In order to whitelist redirect\_uri, provide an entry in the client
if no entry is present, all uri are accepted

## state\_required

State is optional in the sepcifications, however using state is really recommended to have a safe implementation on client side.
Client should send state and verify it, switching state\_required to 1 make state a required parameter when trying to get
the authorization code

## server\_class

Package name of the server class for customizing the OAuth server behavior.
Defaults to Dancer2::Plugin::OAuth2::Server::Simple, the provided simple implementation

# Server Class implementation

To customize the implementation in a more realistic way, the user needs to create a class implementing
the role Dancer2::Plugin::OAuth2::Server::Role , and provide the Class name in the configuration key
server\_class. That role ensures that all the required functions are implemented.
All the function will receive the dsl and settings as first 2 parameters: $dsl, $settings
Those parameters will for instance allows user to access session, are plugin configuration

## login\_resource\_owner

Function that tells if the Resource owner is logged in. It should return 1 if the
user is logged in, return 0 if not. That function is expected to redirect the user to login page if needed.

## confirm\_by\_resource\_owner

Function to tell the plugin if the Resource Owner allowed or denied access to
the Resource Server by the Client. Function receives the client\_id and the list of scopes
requested by the client.
It should return 1 if access is allowed, 0 if access is not allowed, otherwise
it should redirect the user and return undef

## verify\_client

Reference: [http://tools.ietf.org/html/rfc6749#section-4.1.1](http://tools.ietf.org/html/rfc6749#section-4.1.1)

Function to verify if the client asking for an authorization code is known
to the Resource Server and allowed to get an authorization code for the passed
scopes.
The function receives the client id, and an array reference of request scopes, and
the redirect url. The callback should return a list with two elements. The first
element is either 1 or 0 to say that the client is allowed or disallowed, the second element
should be the error message in the case of the client being disallowed.
Note: Even if the redirect url is optional, there can be some security concern if
someone redirects to a compromised server. Because of that, some OAuth2 provider
requried to whitelist the redirect uri by client. To allow client to verify url,
it's passed as last argument to method verifiy\_client

## store\_auth\_code

Function to allow you to store the generated authorization code. After the 2 common parameters,
The Function is passed  the generated auth code, the client id, the auth code validity period in
seconds, the Client redirect URI, and a list of the scopes requested by the Client.
You should save the information to your data store, it can then be retrieved by
the verify\_auth\_code function for verification

## generate\_token

Function to generate a token. After the 2 common parameters, dsl and settings,
that function receives the validity period in seconds, the client id, the list of scopes,
the type of token and the redirect url.
That function should return the token that it generates, and should be unique.

## verify\_auth\_code

Reference: [http://tools.ietf.org/html/rfc6749#section-4.1.3](http://tools.ietf.org/html/rfc6749#section-4.1.3)

Function to verify the authorization code passed from the Client to the
Authorization Server. The function is passed the dsl, the settings, and then
the client\_id, the client\_secret, the authorization code, and the redirect uri.
The Function should verify the authorization code using the rules defined in
the reference RFC above, and return a list with 4 elements. The first element
should be a client identifier (a scalar, or reference) in the case of a valid
authorization code or 0 in the case of an invalid authorization code. The second
element should be the error message in the case of an invalid authorization
code. The third element should be a hash reference of scopes as requested by the
client in the original call for an authorization code. The fourth element should
be a user identifier

## store\_access\_token

Function to allow you to store the generated access and refresh tokens. The
function is passed the dsl, the settings, and then the client identifier as
returned from the verify\_auth\_code callback, the authorization code, the access
token, the refresh\_token, the validity period in seconds, the scope returned
from the verify\_auth\_code callback, and the old refresh token,

Note that the passed authorization code could be undefined, in which case the
access token and refresh tokens were requested by the Client by the use of an
existing refresh token, which will be passed as the old refresh token variable.
In this case you should use the old refresh token to find out the previous
access token and revoke the previous access and refresh tokens (this is \*not\* a
hard requirement according to the OAuth spec, but i would recommend it).
That functions does not need to return anything.
You should save the information to your data store, it can then be retrieved by
the verify\_access\_token callback for verification

## verify\_access\_token

Reference: [http://tools.ietf.org/html/rfc6749#section-7](http://tools.ietf.org/html/rfc6749#section-7)

Function to verify the access token. The function is passed the dsl, the
settings and then the access token, an optional reference to a list of the
scopes and if the access\_token is actually a refresh token. Note that the access
token could be the refresh token, as this method is also called when the Client
uses the refresh token to get a new access token (in which case the value of the
$is\_refresh\_token variable will be true).

The function should verify the access code using the rules defined in the
reference RFC above, and return false if the access token is not valid otherwise
it should return something useful if the access token is valid - since this
method is called by the call to oauth\_scopes you probably need to return a hash
of details that the access token relates to (client id, user id, etc).
In the event of an invalid, expired, etc, access or refresh token you should
return a list where the first element is 0 and the second contains the error
message (almost certainly 'invalid\_grant' in this case)

# AUTHOR

Pierre Vigier <pierre.vigier@gmail.com>

# CONTRIBUTORS

Orignal plugin for mojolicious:

Lee Johnson - `leejo@cpan.org`

With contributions from:

Peter Mottram `peter@sysnix.com`

# COPYRIGHT

Copyright 2016- Pierre Vigier

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO
