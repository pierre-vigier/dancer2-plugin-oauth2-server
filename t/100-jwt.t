use strict;
use Plack::Test;
#use Test::More tests => 43;
use Test::More;
use Test::Deep;
use HTTP::Request;
use HTTP::Request::Common;
use URI;
use URI::QueryParam;
use JSON;

{
    package Implementation;
    use Moo;

    sub jwt_claims {
        my ( $self, %args ) = @_;
        my ( $plugin, $user_id, $client_id, $type, $scopes_ref, $redirect_uri, $jti ) =
            @args{ qw<plugin user_id client_id type scopes redirect_uri jti> };

          return (
            iss => "some iss",
            sub => "not the passed user_id",
          );
    }
}
{
    package Default;
    BEGIN { $ENV{DANCER_ENVIRONMENT} = 'default-jwt'; }
    use Dancer2;
    use Dancer2::Plugin::OAuth2::Server;

    get '/protected-identity' => oauth_scopes 'identity' => sub {
        return "protected route with scope identity";
    };

    get '/protected-other' => oauth_scopes 'other' => sub {
        return "protected route with scope other";
    };

}
my $jwt_secret = 'nova scotia scova notia';

my $app = Default->to_app;
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
use Mojo::JWT;
my $decoded_auth_code = Mojo::JWT->new( secret => $jwt_secret )->decode( $code );
cmp_deeply(
	$decoded_auth_code,
	{
    'type' => 'auth',
    'aud' => 'http://localhost/callback',
    'client' => 'client1',
    'user_id' => undef,
    'exp' => re( '^\d{10}$' ),
    'iat' => re( '^\d{10}$' ),
    'jti' => re( '^.{32}$' ),
    'iss' => "some iss",
    'sub' => "not the passed user_id",
    'scopes' => [
      'identity',
    ]
  },
	'decoded JWT (auth code)',
);

$request  = POST '/oauth/access_token', Content => [ client_id => 'client1', client_secret => 'secret', grant_type => 'authorization_code', code => $code, redirect_uri => 'http://localhost/callback' ];
$response = $test->request($request);
is $response->code, 200, "Access token route working";
my $decoded = from_json( $response->content );
ok exists $decoded->{access_token}, "Access token provided";
ok exists $decoded->{refresh_token}, "Refresh token provided";
my $access_token = $decoded->{access_token};
my $refresh_token = $decoded->{refresh_token};

my $decoded_access = Mojo::JWT->new( secret => $jwt_secret )->decode( $access_token );
my $decoded_refresh = Mojo::JWT->new( secret => $jwt_secret )->decode( $refresh_token );

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
my $decoded_access = Mojo::JWT->new( secret => $jwt_secret )->decode( $new_access_token );

$request  = HTTP::Request->new( GET => '/protected-identity' );
$request->header( Authorization => "Bearer $new_access_token");
$response = $test->request($request);
is $response->code, 200, "With bearer, new access token, protected route OK";
done_testing(); exit;

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

is $error, 'unauthorized_client', "Unauthorized client access";
ok !$code, "Code not provided";
1;

