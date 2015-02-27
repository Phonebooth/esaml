%% @doc SAML Identity Provider (IDP) routines
-module(esaml_idp).

-include("../include/esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-type xml() :: #xmlElement{} | #xmlDocument{}.
-export([generate_metadata/1, generate_authn_response/3, generate_logout_response/3, validate_authn_request/2]).

generate_metadata(IDP = #esaml_idp{org = Org, tech = Tech}) ->
    Xml = esaml:to_xml(#esaml_idp_metadata{
       org = Org,
       tech = Tech,
       certificate = IDP#esaml_idp.certificate,
       cert_chain = IDP#esaml_idp.cert_chain,
       entity_id = IDP#esaml_idp.metadata_uri,
       signed_requests = IDP#esaml_idp.sp_sign_requests,
       login_bindings = IDP#esaml_idp.login_service,
       logout_bindings = IDP#esaml_idp.logout_service}),
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
                {ok, AR} -> AR;
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
