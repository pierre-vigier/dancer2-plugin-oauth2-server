use strict;
use Plack::Test;
use Test::More tests => 5;
use HTTP::Request;
use HTTP::Request::Common;

{
    package DefaultRoute;
    BEGIN { $ENV{DANCER_ENVIRONMENT} = 'routes-overrides'; }
    use Dancer2;
    use Dancer2::Plugin::OAuth2::Server;
}

my $app = DefaultRoute->to_app;
my $test = Plack::Test->create($app);

my $request  = HTTP::Request->new( GET => '/oauth/authorize' );
my $response = $test->request($request);
is $response->code, 404, "Authorize route customized, default one should give 404";

$request  = HTTP::Request->new( POST => '/oauth/access_token' );
$response = $test->request($request);
is $response->code, 404, "Access route customized, default one should give 404";

$request  = HTTP::Request->new( GET => '/test/authorize' );
$response = $test->request($request);
is $response->code, 400, "authorize route created";

$request  = HTTP::Request->new( POST => '/test/access_token' );
$response = $test->request($request);
is $response->code, 400, "access_token route created";

$request  = HTTP::Request->new( GET => '/test/access_token' );
$response = $test->request($request);
is $response->code, 404, "Access token route not available through GET";

1;
