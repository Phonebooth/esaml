%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML for Erlang
-module(esaml).
-behaviour(application).
-behaviour(supervisor).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-export([start/2, stop/1, init/1]).
-export([stale_time/1]).
-export([config/2, config/1, to_xml/1, decode_response/1, decode_assertion/1, validate_assertion/3]).
-export([decode_logout_request/1, decode_logout_response/1, decode_idp_metadata/1, decode_sp_metadata/1]).
-export([decode_authn_request/1]).

-type org() :: #esaml_org{}.
-type contact() :: #esaml_contact{}.
-type sp_metadata() :: #esaml_sp_metadata{}.
-type idp_metadata() :: #esaml_idp_metadata{}.
-type authnreq() :: #esaml_authnreq{}.
-type subject() :: #esaml_subject{}.
-type assertion() :: #esaml_assertion{}.
-type logoutreq() :: #esaml_logoutreq{}.
-type logoutresp() :: #esaml_logoutresp{}.
-type response() :: #esaml_response{}.
-type sp() :: #esaml_sp{}.
-type idp() :: #esaml_idp{}.
-type provider() :: #esaml_sp{} | #esaml_idp{}.
-type binding() :: #esaml_binding{}.
-type saml_record() :: org() | contact() | sp_metadata() | idp_metadata() | authnreq() | subject() | assertion() | logoutreq() | logoutresp() | response() | binding().

-export_type([org/0, contact/0, sp_metadata/0, idp_metadata/0,
    authnreq/0, subject/0, assertion/0, logoutreq/0,
    logoutresp/0, response/0, sp/0, saml_record/0]).

-type localized_string() :: string() | [{Locale :: atom(), LocalizedString :: string()}].
-type name_format() :: email | x509 | windows | krb | persistent | transient | unknown.
-type logout_reason() :: user | admin.
-type status_code() :: success | request_error | response_error | bad_version | authn_failed | bad_attr | denied | bad_binding | unknown.
-type version() :: string().
-type datetime() :: string() | binary().
-type condition() :: #esaml_conditions{}.
-type conditions() :: [condition()].
-export_type([localized_string/0, name_format/0, logout_reason/0, status_code/0, version/0, datetime/0, conditions/0]).

%% @private
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @private
stop(_State) ->
    ok.

%% @private
init([]) ->
    DupeEts = {esaml_ets_table_owner,
        {esaml_util, start_ets, []},
        permanent, 5000, worker, [esaml]},
    {ok,
        {{one_for_one, 60, 600},
        [DupeEts]}}.

%% @doc Retrieve a config record
-spec config(Name :: atom()) -> term() | undefined.
config(N) -> config(N, undefined).
%% @doc Retrieve a config record with default
-spec config(Name :: atom(), Default :: term()) -> term().
config(N, D) ->
    case application:get_env(esaml, N) of
        {ok, V} -> V;
        _ -> D
    end.

-spec nameid_map(string()) -> name_format().
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") -> email;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName") -> x509;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName") -> windows;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos") -> krb;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") -> persistent;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:transient") -> transient;
nameid_map(S) when is_list(S) -> unknown.

rev_nameid_map(permanent) -> "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
rev_nameid_map(email) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
rev_nameid_map(x509) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
rev_nameid_map(windows) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
rev_nameid_map(_) -> "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".

-spec subject_method_map(string()) -> bearer | unknown.
subject_method_map("urn:oasis:names:tc:SAML:2.0:cm:bearer") -> bearer;
subject_method_map(_) -> unknown.

rev_subject_method_map(bearer) -> "urn:oasis:names:tc:SAML:2.0:cm:bearer";
rev_subject_method_map(_) -> unknown.

-spec status_code_map(string()) -> status_code() | atom().
status_code_map("urn:oasis:names:tc:SAML:2.0:status:Success") -> success;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch") -> bad_version;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed") -> authn_failed;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue") -> bad_attr;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:RequestDenied") -> denied;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding") -> bad_binding;
status_code_map(Urn = "urn:" ++ _) -> list_to_atom(lists:last(string:tokens(Urn, ":")));
status_code_map(S) when is_list(S) -> unknown.

-spec rev_status_code_map(status_code()) -> string().
rev_status_code_map(success) -> "urn:oasis:names:tc:SAML:2.0:status:Success";
rev_status_code_map(bad_version) -> "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
rev_status_code_map(authn_failed) -> "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
rev_status_code_map(bad_attr) -> "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
rev_status_code_map(denied) -> "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
rev_status_code_map(bad_binding) -> "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";
rev_status_code_map(_) -> error(bad_status_code).

binding_map("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") -> http_redirect;
binding_map("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") -> http_post;
binding_map("urn:oasis:names:tc:SAML:2.0:bindings:SOAP") -> soap;
binding_map("urn:oasis:names:tc:SAML:2.0:bindings:PAOS") -> paos;
binding_map("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact") -> http_artifact;
binding_map("urn:oasis:names:tc:SAML:2.0:bindings:URI") -> saml_uri;
binding_map(_) -> unknown.

rev_binding_map(http_redirect) -> "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
rev_binding_map(http_post) -> "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
rev_binding_map(soap) -> "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";
rev_binding_map(paos) -> "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
rev_binding_map(http_artifact) -> "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
rev_binding_map(saml_uri) -> "urn:oasis:names:tc:SAML:2.0:bindings:URI";
rev_binding_map(_) -> unknown.

-spec logout_reason_map(string()) -> logout_reason().
logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:user") -> user;
logout_reason_map("urn:oasis:names:tc:SAML:2.0:logout:admin") -> admin;
logout_reason_map(S) when is_list(S) -> unknown.

-spec rev_logout_reason_map(logout_reason()) -> string().
rev_logout_reason_map(user) -> "urn:oasis:names:tc:SAML:2.0:logout:user";
rev_logout_reason_map(admin) -> "urn:oasis:names:tc:SAML:2.0:logout:admin".

-spec common_attrib_map(string()) -> atom().
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.3") -> employeeNumber;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.6") -> eduPersonPrincipalName;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.3") -> mail;
common_attrib_map("urn:oid:2.5.4.42") -> givenName;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.241") -> displayName;
common_attrib_map("urn:oid:2.5.4.3") -> commonName;
common_attrib_map("urn:oid:2.5.4.20") -> telephoneNumber;
common_attrib_map("urn:oid:2.5.4.10") -> organizationName;
common_attrib_map("urn:oid:2.5.4.11") -> organizationalUnitName;
common_attrib_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.9") -> eduPersonScopedAffiliation;
common_attrib_map("urn:oid:2.16.840.1.113730.3.1.4") -> employeeType;
common_attrib_map("urn:oid:0.9.2342.19200300.100.1.1") -> uid;
common_attrib_map("urn:oid:2.5.4.4") -> surName;
common_attrib_map(Uri = "http://" ++ _) -> list_to_atom(lists:last(string:tokens(Uri, "/")));
common_attrib_map(Other) when is_list(Other) -> list_to_atom(Other).

-include("xmerl_xpath_macros.hrl").

decode_authn_request(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:AuthnRequest/@IssueInstant", esaml_authnreq, issue_instant, missing_issue_instant),
        ?xpath_attr_required("/samlp:AuthnRequest/@ID", esaml_authnreq, id, missing_id),
        ?xpath_attr_required("/samlp:AuthnRequest/@Version", esaml_authnreq, version, missing_version),
        ?xpath_attr("/samlp:AuthnRequest/@AssertionConsumerServiceURL", esaml_authnreq, consumer_location),
        ?xpath_attr("/samlp:AuthnRequest/@ProtocolBinding", esaml_authnreq, protocol_binding, fun binding_map/1),
        ?xpath_attr("/samlp:AuthnRequest/@AssertionConsumerServiceIndex", esaml_authnreq, consumer_index),
        ?xpath_attr("/samlp:AuthnRequest/@Destination", esaml_authnreq, destination),
        ?xpath_text("/samlp:AuthnRequest/saml:Issuer/text()", esaml_authnreq, issuer)
    ], #esaml_authnreq{}).

%% @private
-spec decode_idp_metadata(Xml :: #xmlElement{}) -> {ok, #esaml_idp_metadata{}} | {error, term()}.
decode_idp_metadata(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
          {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/md:EntityDescriptor/@entityID", esaml_idp_metadata, entity_id, bad_entity),
        ?xpath_list_recurse("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService",
            esaml_idp_metadata, login_bindings, decode_binding),
        ?xpath_list_recurse("/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService",
            esaml_idp_metadata, logout_bindings, decode_binding),
        ?xpath_attr("/md:EntityDescriptor/md:IDPSSODescriptor/@WantAuthnRequestsSigned",
            esaml_idp_metadata, signed_requests),
        ?xpath_text("/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()",
            esaml_idp_metadata, name_format, fun nameid_map/1),
        ?xpath_text("/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", esaml_idp_metadata, certificate, fun(X) -> base64:decode(list_to_binary(X)) end),
        ?xpath_recurse("/md:EntityDescriptor/md:ContactPerson[@contactType='technical']", esaml_idp_metadata, tech, decode_contact),
        ?xpath_recurse("/md:EntityDescriptor/md:Organization", esaml_idp_metadata, org, decode_org)
    ], #esaml_idp_metadata{}).

%% @private
-spec decode_sp_metadata(Xml :: #xmlElement{}) -> {ok, #esaml_sp_metadata{}} | {error, term()}.
decode_sp_metadata(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
          {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/md:EntityDescriptor/@entityID", esaml_sp_metadata, entity_id, bad_entity),
        ?xpath_list_recurse("/md:EntityDescriptor/md:SPSSODescriptor/md:AssertionConsumerService",
            esaml_sp_metadata, consumer_bindings, decode_binding),
        ?xpath_list_recurse("/md:EntityDescriptor/md:SPSSODescriptor/md:SingleLogoutService",
            esaml_sp_metadata, logout_bindings, decode_binding),
        ?xpath_text("/md:EntityDescriptor/md:SPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", esaml_sp_metadata, certificate, fun(X) -> base64:decode(list_to_binary(X)) end),
        ?xpath_recurse("/md:EntityDescriptor/md:ContactPerson[@contactType='technical']", esaml_sp_metadata, tech, decode_contact),
        ?xpath_recurse("/md:EntityDescriptor/md:Organization", esaml_sp_metadata, org, decode_org)
    ], #esaml_sp_metadata{}).

%% @private
-spec decode_binding(Xml :: #xmlElement{}) -> {ok, #esaml_binding{}} | {error, term()}.
decode_binding(Xml) ->
    Attrs = Xml#xmlElement.attributes,
    Binding = (lists:keyfind('Binding', #xmlAttribute.name, Attrs))#xmlAttribute.value,
    Location = (lists:keyfind('Location', #xmlAttribute.name, Attrs))#xmlAttribute.value,
    Index = case lists:keyfind('Index', #xmlAttribute.name, Attrs) of
                false -> undefined;
                #xmlAttribute{value=Value} -> Value
            end,
    {ok, #esaml_binding{
        type = binding_map(Binding),
        index = Index,
        uri = Location
    }}.

%% @private
-spec decode_org(Xml :: #xmlElement{}) -> {ok, #esaml_org{}} | {error, term()}.
decode_org(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'}],
    esaml_util:threaduntil([
        ?xpath_text_required("/md:Organization/md:OrganizationName[@xml:lang=\"en\"]/text()", esaml_org, name, bad_org),
        ?xpath_text("/md:Organization/md:OrganizationDisplayName[@xml:lang=\"en\"]/text()", esaml_org, displayname),
        ?xpath_text("/md:Organization/md:OrganizationURL[@xml:lang=\"en\"]/text()", esaml_org, url)
    ], #esaml_org{}).

%% @private
-spec decode_contact(Xml :: #xmlElement{}) -> {ok, #esaml_contact{}} | {error, term()}.
decode_contact(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
          {"md", 'urn:oasis:names:tc:SAML:2.0:metadata'}],
    esaml_util:threaduntil([
        ?xpath_text_required("/md:ContactPerson/md:EmailAddress/text()", esaml_contact, email, bad_contact),
        ?xpath_text("/md:ContactPerson/md:GivenName/text()", esaml_contact, name),
        ?xpath_text_append("/md:ContactPerson/md:SurName/text()", esaml_contact, name, " ")
    ], #esaml_contact{}).

%% @private
-spec decode_logout_request(Xml :: #xmlElement{}) -> {ok, #esaml_logoutreq{}} | {error, term()}.
decode_logout_request(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:LogoutRequest/@Version", esaml_logoutreq, version, bad_version),
        ?xpath_attr_required("/samlp:LogoutRequest/@IssueInstant", esaml_logoutreq, issue_instant, bad_response),
        ?xpath_text_required("/samlp:LogoutRequest/saml:NameID/text()", esaml_logoutreq, name, bad_name),
        ?xpath_attr("/samlp:LogoutRequest/@ID", esaml_logoutreq, id),
        ?xpath_attr("/samlp:LogoutRequest/@Destination", esaml_logoutreq, destination),
        ?xpath_attr("/samlp:LogoutRequest/@Reason", esaml_logoutreq, reason, fun logout_reason_map/1),
        ?xpath_text("/samlp:LogoutRequest/saml:Issuer/text()", esaml_logoutreq, issuer)
    ], #esaml_logoutreq{}).

%% @private
-spec decode_logout_response(Xml :: #xmlElement{}) -> {ok, #esaml_logoutresp{}} | {error, term()}.
decode_logout_response(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:LogoutResponse/@Version", esaml_logoutresp, version, bad_version),
        ?xpath_attr_required("/samlp:LogoutResponse/@IssueInstant", esaml_logoutresp, issue_instant, bad_response),
        ?xpath_attr_required("/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value", esaml_logoutresp, status, fun status_code_map/1, bad_response),
        ?xpath_attr("/samlp:LogoutResponse/@Destination", esaml_logoutresp, destination),
        ?xpath_text("/samlp:LogoutResponse/saml:Issuer/text()", esaml_logoutresp, issuer)
    ], #esaml_logoutresp{}).

%% @private
-spec decode_response(Xml :: #xmlElement{}) -> {ok, #esaml_response{}} | {error, term()}.
decode_response(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/samlp:Response/@Version", esaml_response, version, bad_version),
        ?xpath_attr_required("/samlp:Response/@IssueInstant", esaml_response, issue_instant, bad_response),
        ?xpath_attr("/samlp:Response/@Destination", esaml_response, destination),
        ?xpath_text("/samlp:Response/saml:Issuer/text()", esaml_response, issuer),
        ?xpath_attr("/samlp:Response/samlp:Status/samlp:StatusCode/@Value", esaml_response, status, fun status_code_map/1),
        ?xpath_recurse("/samlp:Response/saml:Assertion", esaml_response, assertion, decode_assertion)
    ], #esaml_response{}).

%% @private
-spec decode_assertion(Xml :: #xmlElement{}) -> {ok, #esaml_assertion{}} | {error, term()}.
decode_assertion(Xml) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr_required("/saml:Assertion/@Version", esaml_assertion, version, bad_version),
        ?xpath_attr_required("/saml:Assertion/@IssueInstant", esaml_assertion, issue_instant, bad_assertion),
        ?xpath_attr_required("/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", esaml_assertion, recipient, bad_recipient),
        ?xpath_text("/saml:Assertion/saml:Issuer/text()", esaml_assertion, issuer),
        ?xpath_recurse("/saml:Assertion/saml:Subject", esaml_assertion, subject, decode_assertion_subject),
        ?xpath_recurse("/saml:Assertion/saml:Conditions", esaml_assertion, conditions, decode_assertion_conditions),
        ?xpath_recurse("/saml:Assertion/saml:AttributeStatement", esaml_assertion, attributes, decode_assertion_attributes)
    ], #esaml_assertion{}).

-spec decode_assertion_subject(#xmlElement{}) -> {ok, #esaml_subject{}} | {error, term()}.
decode_assertion_subject(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_text("/saml:Subject/saml:NameID/text()", esaml_subject, name),
        ?xpath_attr("/saml:Subject/saml:SubjectConfirmation/@Method", esaml_subject, confirmation_method, fun subject_method_map/1),
        ?xpath_attr("/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter", esaml_subject, notonorafter)
    ], #esaml_subject{}).

-spec decode_assertion_conditions(#xmlElement{}) -> {ok, conditions()} | {error, term()}.
decode_assertion_conditions(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    esaml_util:threaduntil([
        ?xpath_attr("/saml:Conditions/@NotBefore", esaml_conditions, not_before, fun esaml_util:saml_to_datetime/1),
        ?xpath_attr("/saml:Conditions/@NotOnOrAfter", esaml_conditions, not_on_or_after, fun esaml_util:saml_to_datetime/1),
        ?xpath_text_list("/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", esaml_conditions, audience)
    ], #esaml_conditions{}).

-spec decode_assertion_attributes(#xmlElement{}) -> {ok, [{atom(), string()}]} | {error, term()}.
decode_assertion_attributes(Xml) ->
    Ns = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],
    Attrs = xmerl_xpath:string("/saml:AttributeStatement/saml:Attribute", Xml, [{namespace, Ns}]),
    {ok, lists:foldl(fun(AttrElem, In) ->
        case [X#xmlAttribute.value || X <- AttrElem#xmlElement.attributes, X#xmlAttribute.name =:= 'Name'] of
            [Name] ->
                case xmerl_xpath:string("saml:AttributeValue/text()", AttrElem, [{namespace, Ns}]) of
                    [#xmlText{value = Value}] ->
                        [#esaml_attribute{name=common_attrib_map(Name), values=[Value]} | In];
                    List ->
                        if (length(List) > 0) ->
                            Value = [X#xmlText.value || X <- List, element(1, X) =:= xmlText],
                            [#esaml_attribute{name=common_attrib_map(Name), values=Value} | In];
                        true ->
                            In
                        end
                end;
            _ -> In
        end
    end, [], Attrs)}.

%% @doc Returns the time at which an assertion is considered stale.
%% @private
-spec stale_time(#esaml_assertion{}) -> integer().
stale_time(A) ->
    esaml_util:thread([
        fun(T) ->
            case A#esaml_assertion.subject of
                #esaml_subject{notonorafter = ""} -> T;
                #esaml_subject{notonorafter = Restrict} ->
                    Secs = calendar:datetime_to_gregorian_seconds(
                        esaml_util:saml_to_datetime(Restrict)),
                    if (Secs < T) -> Secs; true -> T end
            end
        end,
        fun(T) ->
            Conds = #esaml_conditions{} = A#esaml_assertion.conditions,
            case Conds#esaml_conditions.not_on_or_after of
                undefined -> T;
                Restrict ->
                    Secs = calendar:datetime_to_gregorian_seconds(
                        esaml_util:saml_to_datetime(Restrict)),
                    if (Secs < T) -> Secs; true -> T end
            end
        end,
        fun(T) ->
            if (T =:= none) ->
                II = A#esaml_assertion.issue_instant,
                IISecs = calendar:datetime_to_gregorian_seconds(
                    esaml_util:saml_to_datetime(II)),
                IISecs + 5*60;
            true ->
                T
            end
        end
    ], none).

check_stale(A) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    NowSecs = calendar:datetime_to_gregorian_seconds(Now),
    T = stale_time(A),
    if (NowSecs > T) ->
        {error, stale_assertion};
    true ->
        A
    end.

%% @doc Parse and validate an assertion, returning it as a record
%% @private
-spec validate_assertion(AssertionXml :: #xmlElement{}, Recipient :: string(), Audience :: string()) ->
        {ok, #esaml_assertion{}} | {error, Reason :: term()}.
validate_assertion(AssertionXml, Recipient, Audience) ->
    case decode_assertion(AssertionXml) of
        {error, Reason} ->
            {error, Reason};
        {ok, Assertion} ->
            esaml_util:threaduntil([
                fun(A) -> case A of
                    #esaml_assertion{version = "2.0"} -> A;
                    _ -> {error, bad_version}
                end end,
                fun(A) -> case A of
                    #esaml_assertion{recipient = Recipient} -> A;
                    _ -> {error, bad_recipient}
                end end,
                fun(A) -> case A of
                    #esaml_assertion{conditions = #esaml_conditions{audience=ClaimedAudiences}} ->
                        case ClaimedAudiences of
                            undefined -> A;
                            _ -> case lists:member(Audience, ClaimedAudiences) of
                                     true -> A;
                                     false -> {error, bad_audience}
                                 end
                        end;
                    _ -> A
                end end,
                fun check_stale/1
            ], Assertion)
    end.

%% @doc Produce cloned elements with xml:lang set to represent
%%      multi-locale strings.
%% @private
-spec lang_elems(#xmlElement{}, localized_string()) -> [#xmlElement{}].
lang_elems(BaseTag, Vals = [{Lang, _} | _]) when is_atom(Lang) ->
    [BaseTag#xmlElement{
        attributes = BaseTag#xmlElement.attributes ++
            [#xmlAttribute{name = 'xml:lang', value = atom_to_list(L)}],
        content = BaseTag#xmlElement.content ++
            [#xmlText{value = V}]} || {L,V} <- Vals];
lang_elems(BaseTag, Val) ->
    [BaseTag#xmlElement{
        attributes = BaseTag#xmlElement.attributes ++
            [#xmlAttribute{name = 'xml:lang', value = "en"}],
        content = BaseTag#xmlElement.content ++
            [#xmlText{value = Val}]}].

%% @doc Convert a SAML request/metadata record into XML
%% @private
-spec to_xml(saml_record()) -> #xmlElement{}.
to_xml(#esaml_authnreq{version = V, issue_instant = Time, destination = Dest, issuer = Issuer, consumer_location = Consumer}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:AuthnRequest',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest},
                      #xmlAttribute{name = 'AssertionConsumerServiceURL', value = Consumer},
                      #xmlAttribute{name = 'ProtocolBinding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}],
        content = [
            #xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', attributes = [#xmlAttribute{name = 'Method', value = "urn:oasis:names:tc:SAML:2.0:cm:bearer"}]}
            ]}
        ]
    });

to_xml(#esaml_logoutreq{version = V, issue_instant = Time, destination = Dest, issuer = Issuer,
                        name = NameID, reason = Reason}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:LogoutRequest',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest},
                      #xmlAttribute{name = 'ProtocolBinding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"},
                      #xmlAttribute{name = 'Reason', value = rev_logout_reason_map(Reason)}],
        content = [
            #xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
            #xmlElement{name = 'saml:NameID', content = [#xmlText{value = NameID}]}
        ]
    });

to_xml(#esaml_logoutresp{version = V, issue_instant  = Time,
    destination = Dest, issuer = Issuer, status = Status}) ->
    Ns = #xmlNamespace{nodes = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    esaml_util:build_nsinfo(Ns, #xmlElement{name = 'samlp:LogoutResponse',
        attributes = [#xmlAttribute{name = 'xmlns:samlp', value = proplists:get_value("samlp", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'xmlns:saml', value = proplists:get_value("saml", Ns#xmlNamespace.nodes)},
                      #xmlAttribute{name = 'IssueInstant', value = Time},
                      #xmlAttribute{name = 'Version', value = V},
                      #xmlAttribute{name = 'Destination', value = Dest},
                      #xmlAttribute{name = 'ProtocolBinding', value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"}],
        content = [
            #xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]},
            #xmlElement{name = 'samlp:Status', content = [
                    #xmlElement{name = 'samlp:StatusCode', content = [
                        #xmlText{value = rev_status_code_map(Status)}]}]}
        ]
    });

to_xml(#esaml_sp_metadata{org = #esaml_org{name = OrgName, displayname = OrgDisplayName,
                                           url = OrgUrl },
                       tech = #esaml_contact{name = TechName, email = TechEmail},
                       signed_requests = SignReq, signed_assertions = SignAss,
                       certificate = CertBin, cert_chain = CertChain, entity_id = EntityID,
                       consumer_bindings = ConsumerServices,
                       logout_bindings = SLOServices
                       }) ->
    Ns = #xmlNamespace{nodes = [{"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
                                {"ds", 'http://www.w3.org/2000/09/xmldsig#'}]},

    MdOrg = #xmlElement{name = 'md:Organization',
        content =
            lang_elems(#xmlElement{name = 'md:OrganizationName'}, OrgName) ++
            lang_elems(#xmlElement{name = 'md:OrganizationDisplayName'}, OrgDisplayName) ++
            lang_elems(#xmlElement{name = 'md:OrganizationURL'}, OrgUrl)
    },

    MdContact = #xmlElement{name = 'md:ContactPerson',
        attributes = [#xmlAttribute{name = 'contactType', value = "technical"}],
        content = [
            #xmlElement{name = 'md:SurName', content = [#xmlText{value = TechName}]},
            #xmlElement{name = 'md:EmailAddress', content = [#xmlText{value = TechEmail}]}
        ]
    },

    KeyDesc = case CertBin of
        undefined -> [];
        C when is_binary(C) ->
            [#xmlElement{name = 'md:KeyDescriptor',
                attributes = [#xmlAttribute{name = 'use', value = "signing"}],
                content = [#xmlElement{name = 'ds:KeyInfo',
                    content = [#xmlElement{name = 'ds:X509Data',
                        content =
                                [#xmlElement{name = 'ds:X509Certificate',
                            content = [#xmlText{value = base64:encode_to_string(CertBin)}]} | 
                                [#xmlElement{name = 'ds:X509Certificate',
                            content = [#xmlText{value = base64:encode_to_string(CertChainBin)}]} || CertChainBin <- CertChain]]}]}]}]
    end,

    SpSso0 = #xmlElement{name = 'md:SPSSODescriptor',
        attributes = [#xmlAttribute{name = 'protocolSupportEnumeration', value = "urn:oasis:names:tc:SAML:2.0:protocol"},
                      #xmlAttribute{name = 'AuthnRequestsSigned', value = atom_to_list(SignReq)},
                      #xmlAttribute{name = 'WantAssertionsSigned', value = atom_to_list(SignAss)}],
        content = KeyDesc ++ build_indexed_endpoint_list(ConsumerServices, 'md:AssertionConsumerService')},

    SpSso = case SLOServices of
        undefined -> SpSso0;
        _ ->
            SpSso0#xmlElement{content = SpSso0#xmlElement.content ++ build_indexed_endpoint_list(SLOServices, 'md:SingleLogoutService')}
    end,

    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'md:EntityDescriptor',
        attributes = [
            #xmlAttribute{name = 'xmlns:md', value = atom_to_list(proplists:get_value("md", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:ds', value = atom_to_list(proplists:get_value("dsig", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'entityID', value = EntityID}
        ], content = [
            SpSso,
            MdOrg,
            MdContact
        ]
    });

to_xml(#esaml_idp_metadata{org = #esaml_org{name = OrgName, displayname = OrgDisplayName,
                                           url = OrgUrl },
                       tech = #esaml_contact{name = TechName, email = TechEmail},
                       signed_requests = SignReq,
                       certificate = CertBin, cert_chain = CertChain, entity_id = EntityID,
                       login_bindings = SSOServices,
                       logout_bindings = SLOServices
                       }) ->
    Ns = #xmlNamespace{nodes = [{"md", 'urn:oasis:names:tc:SAML:2.0:metadata'},
                                {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
                                {"ds", 'http://www.w3.org/2000/09/xmldsig#'},
                                {"xml", 'http://www.w3.org/XML/1998/namespace'}]},

    MdOrg = #xmlElement{name = 'md:Organization',
        content =
            lang_elems(#xmlElement{name = 'md:OrganizationName'}, OrgName) ++
            lang_elems(#xmlElement{name = 'md:OrganizationDisplayName'}, OrgDisplayName) ++
            lang_elems(#xmlElement{name = 'md:OrganizationURL'}, OrgUrl)
    },

    MdContact = #xmlElement{name = 'md:ContactPerson',
        attributes = [#xmlAttribute{name = 'contactType', value = "technical"}],
        content = [
            #xmlElement{name = 'md:SurName', content = [#xmlText{value = TechName}]},
            #xmlElement{name = 'md:EmailAddress', content = [#xmlText{value = TechEmail}]}
        ]
    },

    KeyDesc = case CertBin of
        undefined -> [];
        C when is_binary(C) ->
            [#xmlElement{name = 'md:KeyDescriptor',
                attributes = [#xmlAttribute{name = 'use', value = "signing"}],
                content = [#xmlElement{name = 'ds:KeyInfo',
                    content = [#xmlElement{name = 'ds:X509Data',
                        content =
                                [#xmlElement{name = 'ds:X509Certificate',
                            content = [#xmlText{value = base64:encode_to_string(CertBin)}]} | 
                                [#xmlElement{name = 'ds:X509Certificate',
                            content = [#xmlText{value = base64:encode_to_string(CertChainBin)}]} || CertChainBin <- CertChain]]}]}]}]
    end,

    IdpSso0 = #xmlElement{name = 'md:IDPSSODescriptor',
        attributes = [#xmlAttribute{name = 'protocolSupportEnumeration', value = "urn:oasis:names:tc:SAML:2.0:protocol"},
                      #xmlAttribute{name = 'WantAuthnRequestsSigned', value = atom_to_list(SignReq)}],
        content = KeyDesc
    },

    IdpSso1 = case SLOServices of
        undefined -> IdpSso0;
        [] -> IdpSso0;
        _ ->
            IdpSso0#xmlElement{content = IdpSso0#xmlElement.content ++ [
                #xmlElement{name = 'md:SingleLogoutService',
                    attributes = [#xmlAttribute{name = 'Binding', value = rev_binding_map(B#esaml_binding.type)},
                                  #xmlAttribute{name = 'Location', value = B#esaml_binding.uri}]} || B=#esaml_binding{} <- SLOServices ]
            }
    end,

    IdpSso = case SSOServices of
        undefined -> IdpSso1;
        _ ->
            IdpSso1#xmlElement{content = IdpSso1#xmlElement.content ++ [
                #xmlElement{name = 'md:SingleSignOnService',
                    attributes = [#xmlAttribute{name = 'Binding', value = rev_binding_map(B#esaml_binding.type)},
                                  #xmlAttribute{name = 'Location', value = B#esaml_binding.uri}]} || B=#esaml_binding{} <- SSOServices ]
            }
    end,

    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'md:EntityDescriptor',
        attributes = [
            #xmlAttribute{name = 'xmlns:md', value = atom_to_list(proplists:get_value("md", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:ds', value = atom_to_list(proplists:get_value("ds", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:xml', value = atom_to_list(proplists:get_value("xml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'entityID', value = EntityID}
        ], content = [
            IdpSso,
            MdOrg,
            MdContact
        ]
    });
to_xml(#esaml_subject{name=Name, name_type=NameType, confirmation_method=ConfirmMethod, notonorafter=Expiry, recipient=Recipient, authn_req_id=InResponseTo}) ->
    Ns = #xmlNamespace{nodes=[{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    NameID = #xmlElement{name='saml:NameID',
                         attributes = [#xmlAttribute{name='Format', value=rev_nameid_map(NameType)}],
                         content=[#xmlText{value=Name}]},

    SubjectConfirmationData = #xmlElement{name='saml:SubjectConfirmationData',
                                          attributes = [
                                              #xmlAttribute{name='InResponseTo', value=InResponseTo},
                                              #xmlAttribute{name='Recipient', value=Recipient},
                                              #xmlAttribute{name='NotOnOrAfter', value=Expiry}]},
    SubjectConfirmation = #xmlElement{name='saml:SubjectConfirmation',
                                      attributes = [
                                          #xmlAttribute{name='Method', value=rev_subject_method_map(ConfirmMethod)}],
                                      content = [ SubjectConfirmationData ]},

    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'saml:Subject',
        attributes = [
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))}
        ], content = [
            NameID,
            SubjectConfirmation
        ]
    });
to_xml(#esaml_authn_statement{issue_instant=IssueInstant, session_index=SessionIndex, context_class=Class}) ->
    Ns = #xmlNamespace{nodes=[{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    AuthnClassRef = #xmlElement{name='saml:AuthnContextClassRef',
                                content=[#xmlText{value=Class}]},

    AuthnContext = #xmlElement{name='saml:AuthnContext',
                               content=[AuthnClassRef]},

    esaml_util:build_nsinfo(Ns, #xmlElement{
        name='saml:AuthnStatement',
        attributes = [
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'AuthnInstant', value = IssueInstant},
            #xmlAttribute{name = 'SessionIndex', value = SessionIndex}],
        content = [
            AuthnContext
        ]
    });
to_xml(#esaml_conditions{not_before=NotBefore, not_on_or_after=NotAfter, audience=Audience}) ->
    Ns = #xmlNamespace{nodes=[{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    Attributes = case NotBefore of
                     undefined ->
                         [];
                     _ ->
                         [#xmlAttribute{name='NotBefore', value=esaml_util:datetime_to_saml(NotBefore)}]
                 end,

    Attributes2 = case NotAfter of
                      undefined ->
                          Attributes;
                      _ ->
                          [#xmlAttribute{name='NotOnOrAfter', value=esaml_util:datetime_to_saml(NotAfter)} | Attributes]
                  end,
    Content = case Audience of
                  undefined ->
                      [];
                  _ ->
                      [#xmlElement{name='saml:AudienceRestriction',
                                  content=[ #xmlElement{name='saml:Audience',
                                                        content=[#xmlText{value=Audience}]}]}]
              end,
    esaml_util:build_nsinfo(Ns, #xmlElement{name='saml:Conditions',
                            attributes=Attributes2,
                            content=Content});
to_xml(#esaml_attribute{name=Name, values=Values}) ->
    #xmlElement{name = 'saml:Attribute',
                attributes = [ #xmlAttribute{name = 'Name', value = Name} ],
                content = [ #xmlElement{name='saml:AttributeValue',
                                        content = [#xmlText{value=Value}]} || Value <- Values ]};
to_xml(Assertion=#esaml_assertion{id=ID, issuer=IssuerUri, version=Version, issue_instant=IssueInstant}) ->
    Ns = #xmlNamespace{nodes=[{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    Issuer = #xmlElement{name = 'saml:Issuer',
                         content = [#xmlText{value=IssuerUri}]},

    % TODO: Signature

    Subject = to_xml(Assertion#esaml_assertion.subject),
    Conditions = to_xml(Assertion#esaml_assertion.conditions),

    AuthnStatement = to_xml(Assertion#esaml_assertion.statement),

    Attributes = [ to_xml(Attr) || Attr <- Assertion#esaml_assertion.attributes ],

    AttributeStatement = #xmlElement{name = 'saml:AttributeStatement',
                                     content = Attributes},

    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'saml:Assertion',
        attributes = [
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'ID', value = ID},
            #xmlAttribute{name = 'Version', value = Version},
            #xmlAttribute{name = 'IssueInstant', value = IssueInstant}
        ], content = [
            Issuer,
            Subject,
            Conditions,
            AuthnStatement,
            AttributeStatement
        ]
    });
to_xml(Response=#esaml_response{id=ID, request_id=RequestID, issue_instant=IssueInstant, destination=#esaml_binding{uri=Destination}}) ->
    Ns = #xmlNamespace{nodes=[{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
          {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    Issuer = #xmlElement{name = 'saml:Issuer',
                         content = [#xmlText{value=Response#esaml_response.issuer}]},

    Status = #xmlElement{name = 'samlp:Status',
                         content=[#xmlElement{name='samlp:StatusCode',
                                              attributes=[#xmlAttribute{name='Value', value=rev_status_code_map(Response#esaml_response.status)}]}]},
    Assertion = to_xml(Response#esaml_response.assertion),
    esaml_util:build_nsinfo(Ns, #xmlElement{
        name = 'samlp:Response',
        attributes = [
            #xmlAttribute{name = 'xmlns:saml', value = atom_to_list(proplists:get_value("saml", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'xmlns:samlp', value = atom_to_list(proplists:get_value("samlp", Ns#xmlNamespace.nodes))},
            #xmlAttribute{name = 'ID', value = ID},
            #xmlAttribute{name = 'Version', value = "2.0"},
            #xmlAttribute{name = 'InResponseTo', value = RequestID},
            #xmlAttribute{name = 'Destination', value = Destination},
            #xmlAttribute{name = 'IssueInstant', value = IssueInstant}
        ], content = [
            Issuer,
            Status,
            Assertion
        ]
    });
to_xml(_) -> error("unknown record").

build_indexed_endpoint_list(List, ElementName) ->
    build_indexed_endpoint_list(List, ElementName, 0, []).

build_indexed_endpoint_list([], _, _, Result) ->
    lists:reverse(Result);
build_indexed_endpoint_list([ F | R ], ElementName, Counter, Result) ->
    E = #xmlElement{name = ElementName,
                    attributes = [#xmlAttribute{name = 'Binding', value = rev_binding_map(F#esaml_binding.type)},
                                  #xmlAttribute{name = 'index', value = Counter+1},
                                  #xmlAttribute{name = 'Location', value = F#esaml_binding.uri}]},
    build_indexed_endpoint_list(R, ElementName, Counter+1, [E | Result]).



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

decode_response_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    ?assertMatch({ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", destination = "foo", status = unknown}}, Resp).

decode_response_no_version_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" IssueInstant=\"2013-01-01T01:01:01Z\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_version} = Resp.

decode_response_no_issue_instant_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" Destination=\"foo\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_response} = Resp.

decode_response_destination_optional_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = unknown}} = Resp.

decode_response_status_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", status = success, issuer = "foo"}} = Resp.

decode_response_bad_assertion_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_version} = Resp.

decode_assertion_no_recipient_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\" /></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {error, bad_recipient} = Resp.

decode_assertion_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{issue_instant = "2013-01-01T01:01:01Z", issuer = "foo", status = success, assertion = #esaml_assertion{issue_instant = "test", issuer = "foo", recipient = "foobar123", subject = #esaml_subject{name = "foobar", confirmation_method = bearer}}}} = Resp.

decode_conditions_test() ->
    {Doc, _} = xmerl_scan:string("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"2013-01-01T01:01:01Z\"><saml:Issuer>foo</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></samlp:Status><saml:Assertion Version=\"2.0\" IssueInstant=\"test\"><saml:Issuer>foo</saml:Issuer><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2013-01-01T01:01:01Z\" NotOnOrAfter=\"2013-01-01T03:01:01Z\"><saml:AudienceRestriction><saml:Audience>foobaraudience</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion></samlp:Response>", [{namespace_conformant, true}]),
    Resp = decode_response(Doc),
    {ok, #esaml_response{assertion = #esaml_assertion{conditions = Conds}}} = Resp,
    #esaml_conditions{audience=["foobaraudience"], not_before={{2013,1,1}, {1,1,1}}, not_on_or_after={{2013,1,1}, {3,1,1}}} = Conds.

decode_attributes_test() ->
    {Doc, _} = xmerl_scan:string("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" IssueInstant=\"test\"><saml:Subject><saml:NameID>foobar</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"foobar123\" /></saml:SubjectConfirmation></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"foo\"><saml:AttributeValue>george</saml:AttributeValue><saml:AttributeValue>bar</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><saml:AttributeValue>test@test.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>", [{namespace_conformant, true}]),
    Assertion = decode_assertion(Doc),
    {ok, #esaml_assertion{attributes = Attrs}} = Assertion,
    [#esaml_attribute{name=emailaddress,values=[ "test@test.com"]}, 
     #esaml_attribute{name=foo, values=["george", "bar"]}, 
     #esaml_attribute{name=mail, values=["test@test.com"]}] = lists:sort(Attrs).

validate_assertion_test() ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    DeathSecs = calendar:datetime_to_gregorian_seconds(Now) + 1,
    Death = esaml_util:datetime_to_saml(calendar:gregorian_seconds_to_datetime(DeathSecs)),

    Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},

    E1 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [
                    #xmlElement{name = 'saml:SubjectConfirmationData',
                        attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
                                      #xmlAttribute{name = 'NotOnOrAfter', value = Death}]
                    } ]} ]},
            #xmlElement{name = 'saml:Conditions', content = [
                #xmlElement{name = 'saml:AudienceRestriction', content = [
                    #xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
    }),
    {ok, Assertion} = validate_assertion(E1, "foobar", "foo"),
    #esaml_assertion{issue_instant = "now", recipient = "foobar", subject = #esaml_subject{notonorafter = Death}, conditions = #esaml_conditions{audience=["foo"]}} = Assertion,
    {error, bad_recipient} = validate_assertion(E1, "foo", "something"),
    {error, bad_audience} = validate_assertion(E1, "foobar", "something"),

    E2 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [ ]} ]},
            #xmlElement{name = 'saml:Conditions', content = [
                #xmlElement{name = 'saml:AudienceRestriction', content = [
                    #xmlElement{name = 'saml:Audience', content = [#xmlText{value = "foo"}]}] }] } ]
    }),
    {error, bad_recipient} = validate_assertion(E2, "", "").

validate_stale_assertion_test() ->
    Ns = #xmlNamespace{nodes = [{"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}]},
    OldStamp = esaml_util:datetime_to_saml({{1990,1,1}, {1,1,1}}),
    E1 = esaml_util:build_nsinfo(Ns, #xmlElement{name = 'saml:Assertion',
        attributes = [#xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"}, #xmlAttribute{name = 'Version', value = "2.0"}, #xmlAttribute{name = 'IssueInstant', value = "now"}],
        content = [
            #xmlElement{name = 'saml:Subject', content = [
                #xmlElement{name = 'saml:SubjectConfirmation', content = [
                    #xmlElement{name = 'saml:SubjectConfirmationData',
                        attributes = [#xmlAttribute{name = 'Recipient', value = "foobar"},
                                      #xmlAttribute{name = 'NotOnOrAfter', value = OldStamp}]
                    } ]} ]} ]
    }),
    {error, stale_assertion} = validate_assertion(E1, "foobar", "foo").

-endif.
