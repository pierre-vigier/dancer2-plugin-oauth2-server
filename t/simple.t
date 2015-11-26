use strict;
use Plack::Test;
use Test::More tests => 2;
use HTTP::Request;
use t::lib::Simple::App;

{
    package DefaultRoute;
    use Dancer2;
    use Dancer2::Plugin::OAuth2::Server;
}

my $app = DefaultRoute->to_app;
my $test = Plack::Test->create($app);

my $request  = HTTP::Request->new( GET => '/oauth/authorize' );
my $response = $test->request($request);
is $response->code, 400, "Default authorize route created";

$request  = HTTP::Request->new( POST => '/oauth/access_token' );
$response = $test->request($request);
is $response->code, 400, "Default access_token route created";

$request  = HTTP::Request->new( GET => '/oauth/access_token' );
$response = $test->request($request);
is $response->code, 404, "Access token route not available through GET";

$app = t::lib::Simple::App->to_app;
$test = Plack::Test->create($app);

$request  = HTTP::Request->new( GET => '/oauth/authorize' );
$response = $test->request($request);
is $response->code, 404, "Authorize route customized, default one should give 404";

$request  = HTTP::Request->new( POST => '/oauth/access_token' );
$response = $test->request($request);
is $response->code, 404, "Access route customized, default one should give 404";

$request  = HTTP::Request->new( GET => '/authorize' );
$response = $test->request($request);
is $response->code, 400, "Customized Authorize route created";

$request  = HTTP::Request->new( POST => '/access_token' );
$response = $test->request($request);
is $response->code, 400, "Customized Access route created";

1;
