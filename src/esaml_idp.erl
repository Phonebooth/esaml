%% @doc SAML Identity Provider (IDP) routines
-module(esaml_idp).

-include("../include/esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-type xml() :: #xmlElement{} | #xmlDocument{}.
-export([generate_metadata/1, generate_authn_response/3, generate_logout_response/3, validate_authn_request/2, validate_logout_request/2, validate_logout_response/2]).

%% @doc Generate the metadata for an Identity Provider
-spec generate_metadata(esaml:idp()) -> esaml:idp_metadata().
generate_metadata(IDP = #esaml_idp{org = Org, tech = Tech}) ->
    #esaml_idp_metadata{
       org = Org,
       tech = Tech,
       certificate = IDP#esaml_idp.certificate,
       cert_chain = IDP#esaml_idp.cert_chain,
       entity_id = IDP#esaml_idp.metadata_uri,
       signed_requests = IDP#esaml_idp.sign_requests,
       login_bindings = IDP#esaml_idp.login_service,
       logout_bindings = IDP#esaml_idp.logout_service}.

%% @doc Given an authentication request and an assertion, generate an
%%      authentication response
-spec generate_authn_response(esaml:authnreq(), esaml:assertion(), esaml:idp()) -> esaml:authnresp() | {error, Reason :: term()}.
generate_authn_response(AuthnReq = #esaml_authnreq{issuer=Issuer}, Assertion=#esaml_assertion{}, #esaml_idp{metadata_uri=IDPUri}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),
    SP = esaml_util:load_sp_metadata(Issuer),
    case select_binding(AuthnReq, SP) of
        {error, _}=Err ->
            Err;
        Binding=#esaml_binding{} ->
            #esaml_response{
               id = uuid:to_string(uuid:uuid4()),
               request_id = AuthnReq#esaml_authnreq.id,
               issue_instant = Stamp,
               destination = Binding,
               issuer = IDPUri,
               status = success,
               assertion = Assertion
              }
    end.

%% @private
% Binding is selected using the following rules:
%       1. If the consumer index is set, find the matching index value in the SP metadata.
%       2. If the consumer location is set, but no protocol binding, try and match the URL to one
%          of the known bindings in the SP Metadata. If multiple match, prefer HTTP-POST to HTTP-Redirect
%       3. If both the consumer location and the protocol binding are set, select the matching
%          binding from the SP metadata, assuming it exists.
select_binding(#esaml_authnreq{consumer_index=Index}, #esaml_sp_metadata{consumer_bindings=Bindings}) when Index =/= undefined ->
    case lists:keyfind(Index, #esaml_binding.index, Bindings) of
        false ->
            {error, bad_consumer_index};
        Result ->
            Result
    end;
select_binding(#esaml_authnreq{consumer_location=RequestURL,protocol_binding=undefined}, #esaml_sp_metadata{consumer_bindings=Bindings}) ->
    case lists:filter(fun (#esaml_binding{uri=URL}) -> 
                              case URL of
                                  RequestURL -> true;
                                  _ -> false
                              end
                      end, Bindings) of
        [] ->
            {error, no_matching_url};
        [B=#esaml_binding{}] ->
            B;
        Multiple ->
            case lists:keyfind(http_post, #esaml_binding.type, Multiple) of
                false ->
                    case lists:keyfind(http_redirect, #esaml_binding.type, Multiple) of
                        false ->
                            undefined;
                        Result ->
                            Result
                    end;
                Result ->
                    Result
            end
    end;
select_binding(#esaml_authnreq{consumer_location=URL, protocol_binding=BindingType}, #esaml_sp_metadata{consumer_bindings=Bindings}) ->
    case lists:keyfind(BindingType, #esaml_binding.type, Bindings) of
        B=#esaml_binding{uri=URL} ->
            B;
        _ ->
            {error, no_matching_url}
    end.

%% @doc Generate a logout response
%% TODO: should this take a logout request?
-spec generate_logout_response(string(), esaml:status(), esaml:idp()) -> esaml:logoutresp().
generate_logout_response(Destination, Status, #esaml_idp{metadata_uri=IDPUri}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    #esaml_logoutresp{
       issue_instant = Stamp,
       destination = Destination,
       issuer = IDPUri,
       status = Status}.

%% @doc Validate and parse an AuthnRequest element
-spec validate_authn_request(xml(), esaml:idp()) ->
        {ok, esaml:authnreq()} | {error, Reason :: term()}.
validate_authn_request(Xml, IDP = #esaml_idp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    esaml_util:threaduntil([
        fun(X) ->
            % Not all SPs will sign the authn requests. Verify it if we have it.
            case xmerl_xpath:string("/samlp:AuthnRequest/ds:Signature", X, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case xmerl_dsig:verify(X, IDP#esaml_idp.trusted_fingerprints) of
                        ok -> X;
                        OuterError -> {error, OuterError}
                    end;
                _ -> X
            end
        end,
        fun(X) ->
            case (catch esaml:decode_authn_request(X)) of
                {ok, #esaml_authnreq{consumer_location=undefined, consumer_index=undefined}} -> 
                    {error, missing_consumer_info};
                {ok, AR} ->
                    AR;
                {'EXIT', Reason} -> {error, Reason};
                Err -> Err
            end
        end
    ], Xml).

%% @doc Validate and parse a LogoutRequest element
-spec validate_logout_request(xml(), esaml:idp()) ->
        {ok, esaml:logoutreq()} | {error, Reason :: term()}.
validate_logout_request(Xml, IDP = #esaml_idp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:LogoutRequest", X, [{namespace, Ns}]) of
                [#xmlElement{}] -> X;
                _ -> {error, bad_assertion}
            end
        end,
        fun(X) ->
            % Not all SPs will sign the logout requests. Verify it if we have it.
            % TODO: read the spec for rules about when they must be signed
            case xmerl_xpath:string("/samlp:AuthnRequest/ds:Signature", X, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case xmerl_dsig:verify(X, IDP#esaml_idp.trusted_fingerprints) of
                        ok -> X;
                        OuterError -> {error, OuterError}
                    end;
                _ -> X
            end
        end,
        fun(X) ->
            case (catch esaml:decode_logout_request(X)) of
                {ok, LR} -> LR;
                {'EXIT', Reason} -> {error, Reason};
                Err -> Err
            end
        end
    ], Xml).

%% @doc Validate and parse a LogoutResponse element
-spec validate_logout_response(xml(), esaml:idp()) ->
        {ok, esaml:logoutresp()} | {error, Reason :: term()}.
validate_logout_response(Xml, IDP = #esaml_idp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:LogoutResponse", X, [{namespace, Ns}]) of
                [#xmlElement{}] -> X;
                _ -> {error, bad_assertion}
            end
        end,
        fun(X) ->
            % Signature is optional on the logout_response. Verify it if we have it.
            case xmerl_xpath:string("/samlp:LogoutResponse/ds:Signature", X, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case xmerl_dsig:verify(X, IDP#esaml_idp.trusted_fingerprints) of
                        ok -> X;
                        OuterError -> {error, OuterError}
                    end;
                _ -> X
            end
        end,
        fun(X) ->
            case (catch esaml:decode_logout_response(X)) of
                {ok, LR} -> LR;
                {'EXIT', Reason} -> {error, Reason};
                Err -> Err
            end
        end,
        fun(LR = #esaml_logoutresp{status = success}) -> LR;
           (#esaml_logoutresp{status = S}) -> {error, S} end
    ], Xml).
