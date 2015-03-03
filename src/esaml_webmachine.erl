%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc Convenience functions for use with Webmachine resources
%%
%% This module makes it easier to use esaml in your Webmachine-based web
%% application, by providing easy wrappers around the functions in
%% esaml_binding, esaml_sp, and esaml_idp.
-module(esaml_webmachine).

-include_lib("xmerl/include/xmerl.hrl").
-include("esaml.hrl").

-export([reply_with_authnreq/5, reply_with_metadata/3, reply_with_logoutreq/5, reply_with_logoutresp/6]).
-export([validate_assertion/2, validate_assertion/3, validate_logout/2, validate_authnreq/2]).
-export([reply_with_authnresp/6]).

-type uri() :: string().

%% @doc Reply to a Webmachine request with an AuthnRequest payload
%%
%% RelayState is an arbitrary blob up to 80 bytes long that will
%% be returned verbatim with any assertion that results from this
%% AuthnRequest.
-spec reply_with_authnreq(esaml:sp(), IdPSSOEndpoint :: uri(), RelayState :: binary(), ReqData, Context) -> {any(), ReqData, Context}.
reply_with_authnreq(SP, IDP, RelayState, ReqData, Context) ->
    AuthnRequest = SP:generate_authn_request(IDP),
    Binding = AuthnRequest#esaml_authnreq.consumer_location,
    reply_with_req(Binding, AuthnRequest, SP, RelayState, ReqData, Context).

%% @doc Reply to a Webmachine request with an AuthnResponse payload
%%
%% RelayState is an arbitrary blob up to 80 bytes long that will
%% be returned verbatim with any assertion that results from this
%% AuthnResponse.
-spec reply_with_authnresp(esaml:idp(), AuthnReq :: esaml:authnreq(), Assertion :: esaml:assertion(), RelayState :: binary(), ReqData, Context) -> {any(), ReqData, Context}.
reply_with_authnresp(IDP, AuthnReq, Assertion, RelayState, ReqData, Context) ->
    case IDP:generate_authn_response(AuthnReq, Assertion) of
        {error, no_matching_url} ->
            {{halt, 403}, ReqData, Context};
        Resp=#esaml_response{destination=Binding} ->
            reply_with_req(Binding, Resp, IDP, RelayState, ReqData, Context)
    end.

%% @doc Reply to a Webmachine request with a LogoutRequest payload
%%
%% NameID should be the exact subject name from the assertion you
%% wish to log out.
-spec reply_with_logoutreq(esaml:sp(), IdPSLOEndpoint :: uri(), NameID :: string(), ReqData, Context) -> {any(), ReqData, Context}.
reply_with_logoutreq(SP, IDP, NameID, ReqData, Context) ->
    LogoutReq = SP:generate_logout_request(IDP, NameID),
    %TODO: revisit
    reply_with_req(#esaml_binding{type=http_redirect, uri=IDP}, LogoutReq, SP, <<>>, ReqData, Context).

%% @doc Reply to a Webmachine request with a LogoutResponse payload
%%
%% Be sure to keep the RelayState from the original LogoutRequest that you
%% received to allow the IdP to keep state.
-spec reply_with_logoutresp(esaml:sp(), IdPSLOEndpoint :: uri(), esaml:status_code(), RelayState :: binary(), ReqData, Context) -> {any(), ReqData, Context}.
reply_with_logoutresp(SP=#esaml_sp{}, IDP, Status, RelayState, ReqData, Context) ->
    LogoutResp = SP:generate_logout_response(IDP, Status),
    %TODO: revisit
    reply_with_req(#esaml_binding{type=http_redirect, uri=IDP}, LogoutResp, SP, RelayState, ReqData, Context).
%%
%% @doc Reply to a Webmachine request with a Metadata payload
-spec reply_with_metadata(esaml:sp(), ReqData, Context) -> {any(), ReqData, Context}.
reply_with_metadata(Provider, ReqData, Context) ->
    Metadata = Provider:generate_metadata(),
    Payload = esaml_binding:generate_payload(Metadata, Provider),
    {Payload, wrq:set_resp_headers([{"Content-Type", "text/xml"}], ReqData), Context}.

%% @private
reply_with_req(Binding=#esaml_binding{type=http_redirect}, SAMLRecord, Provider, RelayState, ReqData, Context) ->
    case Binding:encode_http_redirect(Provider, SAMLRecord, RelayState) of
        {error, signed_redirects_unsupported} ->
            % TODO revisit - give it a try with POST?
            reply_with_req(Binding#esaml_binding{type=http_post}, SAMLRecord, Provider, RelayState, ReqData, Context);
        Target ->
            UA = wrq:get_req_header("User-Agent", ReqData),
            IsIE = not (binary:match(list_to_binary(UA), <<"MSIE">>) =:= nomatch),
            if IsIE andalso (byte_size(Target) > 2042) ->
                   reply_with_req(Binding#esaml_binding{type=http_post}, SAMLRecord, Provider, RelayState, ReqData, Context);
               true ->
                   ReqData1 = wrq:set_resp_headers([
                                                    {"Cache-Control", "no-cache"},
                                                    {"Pragma", "no-cache"},
                                                    {"Location", binary_to_list(Target)}
                                                   ], ReqData),
                   ReqData2 = wrq:set_resp_body("Redirecting...", ReqData1),
                   {{halt, 302}, ReqData2, Context}
            end
    end;
reply_with_req(Binding=#esaml_binding{type=http_post}, SAMLRecord, Provider, RelayState, ReqData, Context) ->
    Html = Binding:encode_http_post(Provider, SAMLRecord, RelayState),
    ReqData1 = wrq:set_resp_headers([
                                     {"Cache-Control", "no-cache"},
                                     {"Pragma", "no-cache"}
                                    ], ReqData),
    case wrq:method(ReqData) of
        'POST' ->
            {true, wrq:set_resp_body(Html, ReqData1), Context};
        'GET' ->
            {Html, ReqData1, Context}
    end.

%% @doc Validate and parse an authentication request
-spec validate_authnreq(esaml:idp(), ReqData) -> {esaml:authn_request(), RelayState :: binary(), ReqData} 
                                                 | {error, Reason :: term(), ReqData}.
validate_authnreq(IDP, ReqData) ->
    case wrq:method(ReqData) of
        'POST' ->
            PostVals = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
            SAMLEncoding = proplists:get_value("SAMLEncoding", PostVals),
            SAMLResponse = proplists:get_value("SAMLResponse", PostVals,
                proplists:get_value("SAMLRequest", PostVals)),
            RelayState = proplists:get_value("RelayState", PostVals, <<>>),
            validate_authnreq(IDP, SAMLEncoding, SAMLResponse, RelayState, ReqData);
        'GET' ->
            SAMLEncoding = wrq:get_qs_value("SAMLEncoding", ReqData),
            SAMLResponse = wrq:get_qs_value("SAMLResponse", wrq:get_qs_value("SAMLRequest", ReqData), ReqData),
            RelayState = wrq:get_qs_value("RelayState", <<>>, ReqData),
            validate_authnreq(IDP, SAMLEncoding, SAMLResponse, RelayState, ReqData)
    end.

validate_authnreq(IDP, SAMLEncoding, SAMLResponse, RelayState, _ReqData) ->
    case (catch esaml_binding:decode_response(SAMLEncoding, SAMLResponse)) of
        {'EXIT', Reason} ->
            {error, {bad_decode, Reason}};
        Xml ->
            case IDP:validate_authn_request(Xml) of
                {ok, AuthnReq} -> {AuthnReq, RelayState};
                Err -> Err
            end
    end.


%% @doc Validate and parse a LogoutRequest or LogoutResponse
%%
%% This function handles both REDIRECT and POST bindings.
-spec validate_logout(esaml:provider(), ReqData) ->
        {request, esaml:logoutreq(), RelayState::binary(), ReqData} |
        {response, esaml:logoutresp(), RelayState::binary(), ReqData} |
        {error, Reason :: term(), ReqData}.
validate_logout(SP, ReqData) ->
    case wrq:method(ReqData) of
        'POST' ->
            PostVals = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
            SAMLEncoding = proplists:get_value("SAMLEncoding", PostVals),
            SAMLResponse = proplists:get_value("SAMLResponse", PostVals,
                proplists:get_value("SAMLRequest", PostVals)),
            RelayState = proplists:get_value("RelayState", PostVals, <<>>),
            validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, ReqData);
        'GET' ->
            SAMLEncoding = wrq:get_qs_val("SAMLEncoding", ReqData),
            SAMLResponse = wrq:get_qs_val("SAMLResponse", wrq:get_qs_value("SAMLRequest", ReqData), ReqData),
            RelayState = wrq:get_qs_val("RelayState", <<>>, ReqData),
            validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, ReqData)
    end.

%% @private
validate_logout(SP, SAMLEncoding, SAMLResponse, RelayState, Req2) ->
    case (catch esaml_binding:decode_response(SAMLEncoding, SAMLResponse)) of
        {'EXIT', Reason} ->
            {error, {bad_decode, Reason}, Req2};
        Xml ->
            Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                  {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
            case xmerl_xpath:string("/samlp:LogoutRequest", Xml, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case SP:validate_logout_request(Xml) of
                        {ok, Reqq} -> {request, Reqq, RelayState, Req2};
                        Err -> Err
                    end;
                _ ->
                    case SP:validate_logout_response(Xml) of
                        {ok, Resp} -> {response, Resp, RelayState, Req2};
                        Err -> Err
                    end
            end
    end.

%% @doc Validate and parse an Assertion inside a SAMLResponse
%%
%% This function handles only POST bindings.
-spec validate_assertion(esaml:sp(), Req) ->
        {ok, esaml:assertion(), RelayState :: binary(), Req} |
        {error, Reason :: term(), Req}.
validate_assertion(SP, Req) ->
    validate_assertion(SP, fun(_A, _Digest) -> ok end, Req).

%% @doc Validate and parse an Assertion with duplicate detection
%%
%% This function handles only POST bindings.
%%
%% For the signature of DuplicateFun, see esaml_sp:validate_assertion/3
-spec validate_assertion(esaml:sp(), esaml_sp:dupe_fun(), ReqData) ->
        {ok, esaml:assertion(), RelayState :: binary(), ReqData} |
        {error, Reason :: term(), ReqData}.
validate_assertion(SP, DuplicateFun, ReqData) ->
    PostVals = mochiweb_util:parse_qs(wrq:req_body(ReqData)),
    SAMLEncoding = proplists:get_value("SAMLEncoding", PostVals),
    SAMLResponse = proplists:get_value("SAMLResponse", PostVals),
    RelayState = proplists:get_value("RelayState", PostVals),

    case (catch esaml_binding:decode_response(SAMLEncoding, SAMLResponse)) of
        {'EXIT', Reason} ->
            {error, {bad_decode, Reason}, ReqData};
        Xml ->
            case SP:validate_assertion(Xml, DuplicateFun) of
                {ok, A} -> {ok, A, RelayState, ReqData};
                {error, E} -> {error, E, ReqData}
            end
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.

