%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML HTTP binding handlers
-module(esaml_binding).

-export([decode_request/2, decode_response/2, encode_http_redirect/4, encode_http_post/4]).
-export([generate_payload/2, is_signature_valid/6]).

-include_lib("xmerl/include/xmerl.hrl").
-include("../include/esaml.hrl").
-define(deflate, <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>).

-type uri() :: binary() | string().
-type html_doc() :: binary().
-type xml() :: #xmlElement{} | #xmlDocument{}.

%% @private
-spec xml_payload_type(xml()) -> binary().
xml_payload_type(Xml) ->
    case Xml of
        #xmlDocument{content = [#xmlElement{name = Atom}]} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        #xmlElement{name = Atom} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        _ -> <<"SAMLRequest">>
    end.

%% @private
generate_xmerl(SAMLRecord, Provider, #esaml_binding{type=http_redirect}) ->
    case Provider of
        #esaml_sp{sp_sign_requests=true} ->
            {error, signed_redirects_unsupported};
        #esaml_idp{sign_requests=true} ->
            {error, signed_redirects_unsupported};
        _ ->
            generate_xmerl(SAMLRecord, Provider)
    end;
generate_xmerl(SAMLRecord, Provider, #esaml_binding{}) ->
    generate_xmerl(SAMLRecord, Provider).

generate_xmerl(SAMLRecord, #esaml_sp{sp_sign_requests=true, key=Key, certificate=Cert}) ->
    generate_xmerl(SAMLRecord, Key, Cert);
generate_xmerl(SAMLRecord, #esaml_sp{sp_sign_requests=false}) ->
    generate_xmerl(SAMLRecord);
generate_xmerl(SAMLRecord, #esaml_idp{sign_requests=true, key=Key, certificate=Cert}) ->
    generate_signed_xmerl(SAMLRecord, Key, Cert);
generate_xmerl(SAMLRecord, #esaml_idp{sign_requests=false}) ->
    generate_xmerl(SAMLRecord).

generate_xmerl(SAMLRecord) ->
    Xml = esaml:to_xml(SAMLRecord),
    esaml_util:add_xml_id(Xml).

generate_signed_xmerl(SAMLRecord, Key, Certificate) ->
    Xml = esaml:to_xml(SAMLRecord),
    xmerl_dsig:sign(Xml, Key, Certificate).

serialize_xml(Xml) ->
    lists:flatten(xmerl:export([Xml], xmerl_xml)).

generate_payload(SAMLRecord, #esaml_sp{sp_sign_requests=true, key=Key, certificate=Cert}) ->
    serialize_xml(generate_signed_xmerl(SAMLRecord, Key, Cert));
generate_payload(SAMLRecord, #esaml_idp{sign_requests=true, key=Key, certificate=Cert}) ->
    serialize_xml(generate_signed_xmerl(SAMLRecord, Key, Cert));
generate_payload(SAMLRecord, _) ->
    serialize_xml(generate_xmerl(SAMLRecord)).

decode_request(Encoding, Request) ->
    decode_response(Encoding, Request).

%% @doc Unpack and parse a SAMLResponse with given encoding
-spec decode_response(SAMLEncoding :: binary(), SAMLResponse :: binary()) -> #xmlDocument{}.
decode_response(?deflate, SAMLResponse) ->
	XmlData = binary_to_list(zlib:unzip(base64:decode(SAMLResponse))),
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml;
decode_response(_, SAMLResponse) ->
	Data = base64:decode(SAMLResponse),
    XmlData = case (catch zlib:unzip(Data)) of
        {'EXIT', _} -> binary_to_list(Data);
        Bin -> binary_to_list(Bin)
    end,
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml.

is_signature_valid(rsa_sha, #esaml_sp_metadata{certificate=CertBin}, SAMLRequest, RelayState, SigAlg, Signature) ->
    case public_key:pkix_decode_cert(CertBin, otp) of
        #'OTPCertificate'{tbsCertificate=TBS} ->
            case TBS#'OTPTBSCertificate'.subjectPublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey of
                PublicKey=#'RSAPublicKey'{} ->
                    RelayString = case RelayState of
                                      undefined -> [];
                                      <<>> -> [];
                                      _ -> "RelayState=" ++ RelayState ++ "&"
                                  end,
                    String = iolist_to_binary(["SAMLRequest=", SAMLRequest, "&", RelayString, "SigAlg=", SigAlg]),
                    public_key:verify(String, sha, Signature, PublicKey);
                _ ->
                    false
            end;
        _ ->
            false
    end;
is_signature_valid(_, _, _, _, _, _) ->
    false.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-REDIRECT binding
%%
%% Returns the URI that should be the target of redirection.
-spec encode_http_redirect(Provider :: esaml:provider(), SAMLRecord :: any(), RelayState :: binary(), Binding :: esaml:binding()) -> uri().
encode_http_redirect(Provider, SAMLRecord, RelayState, Binding=#esaml_binding{uri=IdpTarget}) ->
    case generate_xmerl(SAMLRecord, Provider, Binding) of
        {error, Error} ->
            {error, Error};
        SignedXml ->
            Type = xml_payload_type(SignedXml),
            Req = serialize_xml(SignedXml),
            Param = http_uri:encode(base64:encode_to_string(zlib:zip(Req))),
            RelayStateEsc = http_uri:encode(binary_to_list(RelayState)),
            FirstParamDelimiter = case lists:member($?, IdpTarget) of true -> "&"; false -> "?" end,
            iolist_to_binary([IdpTarget, FirstParamDelimiter, "SAMLEncoding=", ?deflate, "&", Type, "=", Param, "&RelayState=", RelayStateEsc])
    end.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding
%%
%% Returns the HTML document to be sent to the browser, containing a
%% form and javascript to automatically submit it.
-spec encode_http_post(Provider :: esaml:provider(), SAMLRecord :: any(), RelayState :: binary(), Binding :: esaml:binding()) -> html_doc().
encode_http_post(Provider, SAMLRecord, RelayState, Binding=#esaml_binding{uri=IdpTarget}) ->
    SignedXml = generate_xmerl(SAMLRecord, Provider, Binding),
    Type = xml_payload_type(SignedXml),
    Req = serialize_xml(SignedXml),
    generate_post_html(Type, IdpTarget, base64:encode(Req), RelayState).

generate_post_html(Type, Dest, Req, RelayState) ->
    iolist_to_binary([<<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body onload=\"document.forms[0].submit()\">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method=\"post\" action=\"">>,Dest,<<"\">
<input type=\"hidden\" name=\"">>,Type,<<"\" value=\"">>,Req,<<"\" />
<input type=\"hidden\" name=\"RelayState\" value=\"">>,RelayState,<<"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.
