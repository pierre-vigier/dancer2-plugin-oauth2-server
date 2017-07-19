use strict;
use Plack::Test;
use Test::More tests => 40;
use HTTP::Request;
use HTTP::Request::Common;
use URI;
use URI::QueryParam;
use JSON;

{
    package Implementation;
    use Moo;
    with 'Dancer2::Plugin::OAuth2::Server::Role';

    sub login_resource_owner      {
        my ($self, %args)  = @_;
        my ($plugin) = @args{ qw<plugin> };
        return (1);
    }
    sub confirm_by_resource_owner {
        my ( $self, %args ) = @_;
        my ($plugin,$client_id, $scopes) = @args{ qw<plugin client_id scopes> };
    }
    sub verify_client             {
        my ( $self, %args ) = @_;
        my ( $plugin, $client_id, $scopes, $redirect_uri ) =
            @args{ qw<plugin client_id scopes redirect_uri> };
        if( $client_id eq 'client1' ) {
            foreach my $s ( @$scopes ) {
                return (0, 'invalid_scope') unless $s eq 'identity';
            }
            return 1;
        }
        if( $client_id eq 'client2' ) {
            foreach my $s ( @$scopes ) {
                return (0, 'invalid_scope') unless $s =~ m/^identity$|^other$/;
            }
            return 1;
        }
        return (0, 'unauthorized client');
    }
    my %AUTH_CODES;
    sub store_auth_code {
        my ( $self, %args ) = @_;
        my ( $plugin, $auth_code, $client_id, $expires_in, $uri, $scopes_ref ) =
            @args{ qw<plugin auth_code client_id expires_in redirect_uri scopes > };
        $AUTH_CODES{$auth_code} = { code => $auth_code, client_id => $client_id, scopes => $scopes_ref };
        return;
    }
    sub verify_auth_code          {
        my ( $self, %args ) = @_;
        my ( $plugin, $client_id, $client_secret, $auth_code, $uri ) =
            @args{ qw/plugin client_id client_secret auth_code redirect_uri / };
        my $error = undef;
        my %scopes = ( client1 => ['identity'], client2 => ['identity','other'] );

        my $code_claims = delete $AUTH_CODES{$auth_code};
        return ( 0,'invalid_grant' ) unless defined $code_claims;
        return ( 0,'invalid_grant' ) unless $code_claims->{client_id} eq $client_id;

        return ( $client_id, $error, $code_claims->{scopes}, 'userid' );
    }
    my %ACCESS_TOKEN;
    my %REFRESH_TOKEN;
    sub store_access_token        {
        my ( $self, %args ) = @_;
        my ( $plugin, $client_id, $auth_code, $access_token, $refresh_token, $expires_in, $scopes, $old_refresh_token )
            = @args{ qw/ plugin client_id auth_code access_token refresh_token expires_in scopes old_refresh_token / };
        if( $old_refresh_token ) {
            $scopes = $REFRESH_TOKEN{$old_refresh_token}->{scopes};
            delete $ACCESS_TOKEN{$REFRESH_TOKEN{$old_refresh_token}->{access_token}};
            delete $REFRESH_TOKEN{$old_refresh_token};
        }
        $ACCESS_TOKEN{$access_token} = { client_id => $client_id , scopes => $scopes, refresh_token => $refresh_token//undef } if $access_token;
        $REFRESH_TOKEN{$refresh_token} = { client_id => $client_id , scopes => $scopes, access_token => $access_token//undef} if $refresh_token;
        return;
    }
    sub verify_access_token       {
        my ( $self, %args ) = @_;
        my ( $plugin, $access_token,$scopes_ref, $is_refresh_token ) =
            @args{ qw<plugin access_token scopes is_refresh_token> };
        if( $is_refresh_token ) {
            if( my $token = $REFRESH_TOKEN{$access_token} ) {
                return $token->{client_id};
            }
        } else {
            if( my $token = $ACCESS_TOKEN{$access_token} ) {
                foreach my $asked ( @$scopes_ref ) {
                    return (0, 'invalid_grant') unless grep { $asked eq $_ } @{ $token->{scopes} };
                }
                return $token->{client_id};
            }
        }
        return (0, 'invalig_grant');
    }
}
{
    package Custom;
    BEGIN { $ENV{DANCER_ENVIRONMENT} = 'custom-implementation'; }
    use Dancer2;
    use Dancer2::Plugin::OAuth2::Server;

    get '/protected-identity' => oauth_scopes 'identity' => sub {
        return "protected route with scope identity";
    };

    get '/protected-other' => oauth_scopes 'other' => sub {
        return "protected route with scope other";
    };

}

my $app = Custom->to_app;
my $test = Plack::Test->create($app);

my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'client1' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'identity' );
$uri->query_param( state => 'mystate' );
my $request  = HTTP::Request->new( GET => $uri );
my $response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
is $uri->query_param( 'state' ), 'mystate', "State returned succesfully";
my $code = $uri->query_param( 'code' );
$request  = POST '/oauth/access_token', Content => [ client_id => 'client1', client_secret => 'secret', grant_type => 'authorization_code', code => $code, redirect_uri => 'http://localhost/callback' ];
$response = $test->request($request);
is $response->code, 200, "Access token route working";
my $decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";
my $access_token = $decoded->{access_token};
my $refresh_token = $decoded->{refresh_token};

$request  = HTTP::Request->new( GET => '/protected-identity' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, protected route OK";

$request  = HTTP::Request->new( GET => '/protected-other' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 400, "With bearer, protected route with another scope KO";

$request  = POST '/oauth/access_token', Content => [ client_id => 'client1', client_secret => 'secret', grant_type => 'refresh_token', refresh_token => $refresh_token ];
$response = $test->request($request);
is $response->code, 200, "Refresh access token succesfully";
$decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";
my $new_access_token = $decoded->{access_token};
my $new_refresh_token = $decoded->{refresh_token};
isnt $new_access_token, $access_token, "Access token has changed";
isnt $new_refresh_token, $refresh_token, "Refresh token has changed";
#ok exists $decoded->{access_token}, "Access token provided";

$request  = HTTP::Request->new( GET => '/protected-identity' );
$request->header( Authorization => "Bearer $new_access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, new access token, protected route OK";

#check if access asked for 2 scopes
my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'client2' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'identity other' );
$uri->query_param( state => 'mystate' );
$request  = HTTP::Request->new( GET => $uri );
$response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
is $uri->query_param( 'state' ), 'mystate', "State returned succesfully";
my $code = $uri->query_param( 'code' );

$request  = POST '/oauth/access_token', Content => [ client_id => 'client2', client_secret => 'secret2', grant_type => 'authorization_code', code => $code, redirect_uri => 'http://localhost/callback' ];
$response = $test->request($request);
is $response->code, 200, "Access token route working";
my $decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";
my $access_token = $decoded->{access_token};
my $refresh_token = $decoded->{refresh_token};

$request  = HTTP::Request->new( GET => '/protected-identity' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, protected route OK";

$request  = HTTP::Request->new( GET => '/protected-other' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, protected route with another scope OK for client2";

#client 2 can access both routes, but if it asks only one scope
my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'client2' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'identity' );
$uri->query_param( state => 'mystate' );
$request  = HTTP::Request->new( GET => $uri );
$response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
is $uri->query_param( 'state' ), 'mystate', "State returned succesfully";
my $code = $uri->query_param( 'code' );

$request  = POST '/oauth/access_token', Content => [ client_id => 'client2', client_secret => 'secret2', grant_type => 'authorization_code', code => $code, redirect_uri => 'http://localhost/callback' ];
$response = $test->request($request);
is $response->code, 200, "Access token route working";
my $decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";
my $access_token = $decoded->{access_token};
my $refresh_token = $decoded->{refresh_token};

$request  = HTTP::Request->new( GET => '/protected-identity' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, protected route OK";

$request  = HTTP::Request->new( GET => '/protected-other' );
$request->header( Authorization => "Bearer $access_token");
$response = $test->request($request);
is $response->code, 400, "With bearer, protected route with another scope KO for client2, no scope asked";

#client 2 can access both routes, but if it asks only one scope
my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'client2' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'identity' );
$uri->query_param( state => 'mystate' );
$request  = HTTP::Request->new( GET => $uri );
$response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
my $code = $uri->query_param( 'code' );

$request  = POST '/oauth/access_token', Content => [ client_id => 'client2', client_secret => 'secret2', grant_type => 'authorization_code', code => $code, redirect_uri => 'http://localhost/callback' ];
$response = $test->request($request);
is $response->code, 200, "Access token route working";
my $decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";

#try to use the same code a second time
$response = $test->request($request);
is $response->code, 400, "Access token route not working, authorization code already consumed";
my $decoded = from_json( $response->content );
ok !exists $decoded->{access_token}, "Access token not provided";
ok !exists $decoded->{refresh_token}, "Refresh token not provided";

#Wrong scope
my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'client1' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'wrong' );
$request  = HTTP::Request->new( GET => $uri );
$response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
my $error = $uri->query_param( 'error' );
$code = $uri->query_param( 'code' );
is $error, 'invalid_scope', "Invalid scope error";
ok !$code, "Code not provided";

#Wrong client
my $uri = URI->new( '/oauth/authorize' );
$uri->query_param( client_id => 'nonauthorized' );
$uri->query_param( redirect_uri => 'http://localhost/callback' );
$uri->query_param( response_type => 'code' );
$uri->query_param( scope => 'identity' );
$request  = HTTP::Request->new( GET => $uri );
$response = $test->request($request);
is $response->code, 302, "get a redirection header";
$uri = URI->new( $response->header('location') );
my $error = $uri->query_param( 'error' );
$code = $uri->query_param( 'code' );

is $error, 'unauthorized client', "Unauthorized client access";
ok !$code, "Code not provided";
1;
