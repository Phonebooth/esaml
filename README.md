An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IDP and can be used in production.

IDP functionality is planned to be added in the future.

# Using esaml

To use esaml in a cowboy app you need to do three things:

1. Add the /saml/:operation route to esaml_cowboy_handler in your cowboy_router config
2. Write a callback module that implements the esaml_sp behaviour
3. Supply appropriate configuration to esaml, either via app.config or through the cowboy_router config


## Example configuration

### cowboy

    {"/saml/[:operation]", esaml_cowboy_handler, [
        {module, esaml_sp_default},
        {base_uri, "http://example.com/saml"}}
        %% will be used for http://example.com/saml/consume
        %% and http://example.com/saml/metadata
    ]},

### sys.config

    {esaml, [
        {sp_certificate, "/x/w/e/l/src/cert"},
        {sp_private_key, undefined},
        {tech_contact, {email, "admin@example.com", name: "John Doe"}},
        {idp_sso_target, "https://app.onelogin.com/saml/signon/364152"},
    ]},


TODO: more documentation and stuff
