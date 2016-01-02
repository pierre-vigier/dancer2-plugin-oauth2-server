[![Build Status](https://travis-ci.org/pierre-vigier/dancer2-plugin-oauth2-server.svg?branch=master)](https://travis-ci.org/pierre-vigier/dancer2-plugin-oauth2-server)

# NAME

Dancer2::Plugin::OAuth2::Server - Easier implementation of an OAuth2 Authorization Server / Resource Server with Dancer2
Port of Mojolicious implementation : https://github.com/G3S/mojolicious-plugin-oauth2-server

# SYNOPSIS

    use Dancer2::Plugin::OAuth2::Server;

    To protect a route, declare it like following:

    get '/protected' => oauth_scopes 'desired_scope' => sub { ... }

# DESCRIPTION

Dancer2::Plugin::OAuth2::Server is a port of Mojolicious plugin for OAuth2 server

# CONFIGURATION

## state\_required

State is optional in the sepcifications, however using state is really recommended to have a safe implementation on client side.
Client should send state and verify it, switching state\_required to 1 make state a required parameter when trying to get 
the authorization code

# AUTHOR

Pierre Vigier &lt;pierre.vigier@gmail.com>

# COPYRIGHT

Copyright 2015- Pierre Vigier

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO
