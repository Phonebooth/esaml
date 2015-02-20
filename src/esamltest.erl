-module(esamltest).

-compile(export_all).

-include("../include/esaml.hrl").

init() ->
    application:start(crypto),
    application:start(xmerl),
    application:start(asn1),
    application:start(public_key),
    application:start(ssl),
    application:start(inets),
    application:start(ranch),
    application:start(cowlib),
    application:start(cowboy),
    application:start(esaml).

sp1() ->
    % Load the certificate and private key for the SP
    PrivKey = esaml_util:load_private_key("server.key"),
    Cert = esaml_util:load_certificate("server.crt"),
    % We build all of our URLs (in metadata, and in requests) based on this
    Base = "http://some.hostname.com/saml",
    % Certificate fingerprints to accept from our IDP
    FPs = ["6b:d1:24:4b:38:cf:6c:1f:4e:53:56:c5:c8:90:63:68:55:5e:27:28"],

    esaml_sp:setup(#esaml_sp{
        key = PrivKey,
        certificate = Cert,
        trusted_fingerprints = FPs,
        consume_uri = Base ++ "/consume",
        metadata_uri = Base ++ "/metadata",
        org = #esaml_org{
            name = "Foo Bar",
            displayname = "Foo Bar",
            url = "http://some.hostname.com"
        },
        tech = #esaml_contact{
            name = "Foo Bar",
            email = "foo@bar.com"
        }
    }).

idp1() ->
    % Load the certificate and private key for the SP
    PrivKey = esaml_util:load_private_key("server.key"),
    Cert = esaml_util:load_certificate("server.crt"),
    % We build all of our URLs (in metadata, and in requests) based on this
    Base = "https://auth.republicdev.info/saml",

    #esaml_idp{
        key = PrivKey,
        certificate = Cert,
        artifact_resolution_uri = Base ++ "/artifact_resolution",
        login_uri = Base ++ "/login",
        metadata_uri = Base ++ "/metadata",
        logout_uri = Base ++ "/logout",
        org = #esaml_org{
            % example of multi-lingual data -- only works in #esaml_org{}
            name = [{en, "Foo Bar"}, {de, "Das Foo Bar"}],
            displayname = "Foo Bar",
            url = "http://some.hostname.com"
        },
        tech = #esaml_contact{
            name = "Foo Bar",
            email = "foo@bar.com"
        }
    }.

