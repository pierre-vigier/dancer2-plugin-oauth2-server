package Dancer2::Plugin::OAuth2::Server::Role;
use Moo::Role;

requires 'login_resource_owner';
requires 'confirm_by_resource_owner';
requires 'verify_client';
requires 'store_auth_code';

1;
