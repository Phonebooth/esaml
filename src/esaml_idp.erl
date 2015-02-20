%% @doc SAML Identity Provider (IDP) routines
-module(esaml_idp).

-include("../include/esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-export([generate_metadata/1, generate_authn_response/3, generate_logout_response/3]).

generate_metadata(IDP = #esaml_idp{org = Org, tech = Tech}) ->
    Xml = esaml:to_xml(#esaml_idp_metadata{
       org = Org,
       tech = Tech,
       certificate = IDP#esaml_idp.certificate,
       cert_chain = IDP#esaml_idp.cert_chain,
       entity_id = IDP#esaml_idp.metadata_uri,
       login_location = IDP#esaml_idp.login_uri,
       logout_location = IDP#esaml_idp.logout_uri}),
    xmerl_dsig:sign(Xml, IDP#esaml_idp.key, IDP#esaml_idp.certificate).

generate_authn_response(AuthnReq = #esaml_authnreq{consumer_location=ACSUrl}, Assertion=#esaml_assertion{}, IDP = #esaml_idp{metadata_uri=IDPUri}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),
    Xml = esaml:to_xml(#esaml_response{
                  request_id = AuthnReq#esaml_authnreq.id,
                  issue_instant = Stamp,
                  destination = ACSUrl,
                  issuer = IDPUri,
                  status = success,
                  assertion = Assertion
                 }),
    xmerl_dsig:sign(Xml, IDP#esaml_idp.key, IDP#esaml_idp.certificate).

generate_logout_response(Destination, Status, IDP = #esaml_idp{metadata_uri=IDPUri}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    Xml = esaml:to_xml(#esaml_logoutresp{
                          issue_instant = Stamp,
                          destination = Destination,
                          issuer = IDPUri,
                          status = Status
    }),
    xmerl_dsig:sign(Xml, IDP#esaml_idp.key, IDP#esaml_idp.certificate).
