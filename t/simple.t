use strict;
use Plack::Test;
use Test::More tests => 2;
use HTTP::Request;


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

1;
