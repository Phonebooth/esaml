%% @doc SAML Identity Provider (IDP) routines
-module(esaml_idp).

-include("../include/esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-export([generate_metadata/1, generate_authn_response/2, generate_logout_response/3]).

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

generate_authn_response(AuthnReq = #esaml_authnreq{consumer_location=ACSUrl}, IDP = #esaml_idp{metadata_uri=IDPUri}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),
    Stamp2 = esaml_util:datetime_to_saml(calendar:gregorian_seconds_to_datetime(calendar:datetime_to_gregorian_seconds(Now) + 3600)),
    Xml = esaml:to_xml(#esaml_response{
                  request_id = AuthnReq#esaml_authnreq.id,
                  issue_instant = Stamp,
                  destination = ACSUrl,
                  issuer = IDPUri,
                  status = success,
                  assertion = #esaml_assertion{
                                 issue_instant = Stamp,
                                 recipient = AuthnReq#esaml_authnreq.issuer,
                                 issuer = IDPUri,
                                 subject = #esaml_subject{
                                              name = "AdamCook",
                                              recipient = ACSUrl,
                                              authn_req_id = AuthnReq#esaml_authnreq.id,
                                              notonorafter = Stamp2
                                             },
                                 statement = #esaml_authn_statement{
                                              issue_instant = Stamp,
                                              session_index = "session_1",
                                              context_class = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                                             },
                                 attributes = [{email, "test2@bandwidth.com"},
                                               {givenName, "John"},
                                               {sn, "Smith"},
                                               {memberOf, "rw_communityuser"}]
                                }
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
