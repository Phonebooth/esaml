%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% data types / message records

-include_lib("public_key/include/public_key.hrl").

-record(esaml_org, {
	name = "" :: esaml:localized_string(),
	displayname = "" :: esaml:localized_string(),
	url = "" :: esaml:localized_string()}).

-record(esaml_contact, {
	name = "" :: string(),
	email = "" :: string()}).

-record(esaml_sp_metadata, {
	org = #esaml_org{} :: esaml:org(),
	tech = #esaml_contact{} :: esaml:contact(),
	signed_requests = true :: boolean(),
	signed_assertions = true :: boolean(),
	certificate :: binary() | undefined,
	cert_chain = [] :: [binary()],
	entity_id = "" :: string(),
	consumer_bindings = [] :: [esaml:binding()],
	logout_bindings = [] :: [esaml:binding()]}).

-record(esaml_idp_metadata, {
	org = #esaml_org{} :: esaml:org(),
	tech = #esaml_contact{} :: esaml:contact(),
	signed_requests = true :: boolean(),
	certificate :: binary() | undefined,
        cert_chain = [] :: [binary()],
	entity_id = "" :: string(),
	login_bindings :: [esaml:binding()],
	logout_bindings :: [esaml:binding()] | undefined,
	name_format = unknown :: esaml:name_format()}).

-record(esaml_authnreq, {
        id = "" :: string(),
	version = "2.0" :: esaml:version(),
	issue_instant = "" :: esaml:datetime(),
	destination = "" :: string(),
	issuer = "" :: string(),
        consumer_index :: integer(),
        protocol_binding :: atom(),
	consumer_location = "" :: string()}).

-record(esaml_subject, {
	name = "" :: string(),
        name_type = transient :: transient | permanent | email,
	confirmation_method = bearer :: atom(),
        authn_req_id,
        recipient,
	notonorafter = "" :: esaml:datetime()}).

-record(esaml_authn_statement, {
        issue_instant,
        session_index,
        context_class
        }).

-record(esaml_conditions, {
          not_before :: esaml:datetime(),
          not_on_or_after :: esaml:datetime(),
          audience :: [string()] | undefined}).

-record(esaml_assertion, {
        id = "" :: string(),
	version = "2.0" :: esaml:version(),
	issue_instant = "" :: esaml:datetime(),
	recipient = "" :: string(),
	issuer = "" :: string(),
	subject = #esaml_subject{} :: esaml:subject(),
        statement,
	conditions = #esaml_conditions{} :: esaml:conditions(),
	attributes = [] :: proplists:proplist()}).

-record(esaml_attribute, {
          name,
          values = []}).

-record(esaml_logoutreq, {
        id :: string(),
	version = "2.0" :: esaml:version(),
	issue_instant = "" :: esaml:datetime(),
	destination = "" :: string(),
	issuer = "" :: string(),
	name = "" :: string(),
	reason = user :: esaml:logout_reason()}).

-record(esaml_logoutresp, {
        request_id :: string(),
	version = "2.0" :: esaml:version(),
	issue_instant = "" :: esaml:datetime(),
	destination = "" :: string(),
	issuer = "" :: string(),
	status = unknown :: esaml:status_code()}).

-record(esaml_response, {
        id = "" :: string(),
        request_id = "" :: string(),
	version = "2.0" :: esaml:version(),
	issue_instant = "" :: esaml:datetime(),
	destination = "" :: string(),
	issuer = "" :: string(),
	status = unknown :: esaml:status_code(),
	assertion = #esaml_assertion{} :: esaml:assertion()}).

-record(esaml_binding, {
        type :: http_redirect | http_post,
        index :: integer(),
        uri :: string()}).

%% state records

-record(esaml_sp, {
	org = #esaml_org{} :: esaml:org(),
	tech = #esaml_contact{} :: esaml:contact(),
	key :: #'RSAPrivateKey'{} | undefined,
	certificate :: binary() | undefined,
	cert_chain = [] :: [binary()],
	sp_sign_requests = false :: boolean(),
	idp_signs_assertions = true :: boolean(),
	idp_signs_envelopes = true :: boolean(),
	idp_signs_logout_requests = true :: boolean(),
	sp_sign_metadata = false :: boolean(),
	trusted_fingerprints = [] :: [string() | binary()],
	metadata_uri = "" :: string(),
	consume_service :: [esaml:binding()],
	logout_service :: [esaml:binding()]}).

-record(esaml_idp, {
         org = #esaml_org{} :: esaml:org(),
         tech = #esaml_contact{} :: esaml:contact(),
         sign_requests = true :: boolean(),
         trusted_fingerprints = [] :: [string() | binary()],
         key :: #'RSAPrivateKey'{} | undefined,
         certificate :: binary() | undefined,
         cert_chain = [] :: [binary()],
         metadata_uri = "" :: string(),
         artifact_resolution :: [esaml:binding()],
         login_service :: [esaml:binding()],
         logout_service :: [esaml:binding()]}).
