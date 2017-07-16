requires 'perl', '5.008005';

requires "Dancer2" => "0.163000";
requires "Dancer2::Plugin";
requires "Crypt::PRNG";
requires "URI";
requires "URI::QueryParam";
requires "Class::Load";
requires "Carp";
requires "MIME::Base64";
requires "Net::OAuth2::AuthorizationServer";

on test => sub {
    requires 'Test::More', '0.96';
    requires 'HTTP::Request';
    requires 'Plack::Test';
    requires 'YAML::XS';
    requires 'JSON';
};
