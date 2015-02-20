%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

-module(idp_handler).
-include("../../../include/esaml.hrl").

-record(state, {idp, sp}).
-export([init/3, handle/2, terminate/3]).

init(_Transport, Req, _Args) ->
    % Load the certificate and private key for the SP
    PrivKey = esaml_util:load_private_key("server.key"),
    Cert = esaml_util:load_certificate("server.crt"),
    % We build all of our URLs (in metadata, and in requests) based on this
    Base = "http://localhost:8080/saml",

    IDP = #esaml_idp{
        key = PrivKey,
        certificate = Cert,
        artifact_resolution_uri = Base ++ "/artifact_resolution",
        login_uri = Base ++ "/login",
        metadata_uri = Base ++ "/metadata",
        logout_uri = Base ++ "/logout",
        org = #esaml_org{
            % example of multi-lingual data -- only works in #esaml_org{}
            name = [{en, "Foo Bar"}],
            displayname = "Foo Bar",
            url = "http://some.hostname.com"
        },
        tech = #esaml_contact{
            name = "Foo Bar",
            email = "foo@bar.com"
        }
    },
    {ok, Req, #state{idp = IDP}}.

handle(Req, S = #state{}) ->
    {Operation, Req2} = cowboy_req:binding(operation, Req),
    {Method, Req3} = cowboy_req:method(Req2),
    handle(Method, Operation, Req3, S).

% Return our SP metadata as signed XML
handle(<<"GET">>, <<"metadata">>, Req, S = #state{idp = IDP}) ->
    {ok, Req2} = esaml_cowboy:reply_with_metadata(IDP, Req),
    {ok, Req2, S};
handle(<<"GET">>, <<"login">>, Req, S = #state{idp = IDP}) ->
    {QS, Req2} = cowboy_req:qs_vals(Req),
    RelayState = proplists:get_value(<<"RelayState">>, QS),
    SAMLRequest = esaml_binding:decode_request(proplists:get_value(<<"SAMLEncoding">>, QS), proplists:get_value(<<"SAMLRequest">>, QS)),
    io:format("~p~n", [SAMLRequest]),
    {ok, AuthnRequest} = esaml:decode_authn_request(SAMLRequest),
    io:format("~p~n", [AuthnRequest]),
    {ok, Req3} = esaml_cowboy:reply_with_authnresp(IDP, AuthnRequest, RelayState, Req2),
    {ok, Req3, S};
handle(<<"GET">>, <<"logout">>, Req, S = #state{idp = IDP}) ->
    {QS, Req2} = cowboy_req:qs_vals(Req),
    RelayState = proplists:get_value(<<"RelayState">>, QS),
    SAMLRequest = esaml_binding:decode_request(proplists:get_value(<<"SAMLEncoding">>, QS), proplists:get_value(<<"SAMLRequest">>, QS)),
    io:format("~p~n", [SAMLRequest]),
    {ok, LogoutRequest} = esaml:decode_logout_request(SAMLRequest),
    io:format("~p~n", [LogoutRequest]),
    Metadata = esaml_util:load_sp_metadata(LogoutRequest#esaml_logoutreq.issuer),
    io:format("SP Metadata: ~p~n", [Metadata]),
    {ok, Req3} = esaml_cowboy:reply_with_logoutresp(IDP, Metadata#esaml_sp_metadata.logout_location, success, RelayState, Req2),
    {ok, Req3, S}.

terminate(_Reason, _Req, _State) -> ok.
