package t::lib::Simple::App;
use Dancer2;
use Dancer2::Plugin::OAuth2::Server;

get '/protected-identity' => oauth_scopes 'identity' => sub {
    return "protected route with scope identity";
};

get '/protected-other' => oauth_scopes 'other' => sub {
    return "protected route with scope other";
};

1;
