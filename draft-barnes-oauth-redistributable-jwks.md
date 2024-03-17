---
title: "Signed JWK Sets"
abbrev: "Signed JWK Sets"
category: info

docname: draft-barnes-oauth-redistributable-jwks-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "bifurcation/redistributable-jwks"
  latest: "https://bifurcation.github.io/redistributable-jwks/draft-barnes-oauth-redistributable-jwks.html"

author:
 -
    fullname: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    fullname: Sharon Goldberg
    organization: BastionZero, Inc.
    email: goldbe@bastionzero.com

normative:

informative:
  OIDC-Discovery:
    target: https://openid.net/specs/openid-connect-discovery-1_0.html
    title: "OpenID Connect Discovery 1.0 incorporating errata set 2"
    date: 2023-12-15
  OpenPubkey:
    target: https://www.bastionzero.com/openpubkey
    title: "OpenPubkey"

--- abstract

A relying party verifying a JSON Web Token (JWT) needs to verify that the public
key used to verify the signature legitimately represents the issuer represented
in the "iss" claim of the JWT.  Today, relying parties commonly use the "iss"
claim to fetch a set of authorized signing keys over HTTPS, relying on the
security of HTTPS to establish the authority of the downloaded keys for that
issuer.  The ephemerality of this proof of authority makes it unsuitable for
use cases where a JWT might need to be verified for some time.  In this
document, we define a format for Signed JWK Sets, which establish the authority
of a key using a signed object instead of an HTTPS connection.

--- middle

# Introduction

A relying party verifying a JSON Web Token (JWT) {{!RFC7519}} needs to verify
that the public key used to verify the signature legitimately represents the
issuer represented in the "iss" claim of the JWT.

Today, relying parties commonly use the `iss` claim to fetch a set of authorized
signing keys over HTTPS, relying on the security of HTTPS to establish the
authority of the downloaded keys for that issuer.  For example, in OpenID
Connect Discovery {{OIDC-Discovery}}, the `iss` claim is used to form a URL
from which issuer metadata is downloaded over HTTPS.  The issuer's JWK set is
linked via the `jwks_uri` field in the metadata.  The SD-JWT-VC specification
describes a similar HTTPS-based mechanism for discovering the valid keys for an
issuer (see {{Section 5 of ?I-D.ietf-oauth-sd-jwt-vc}}).

These HTTPS-based authority mechanisms are "live", in the sense that they can
only prove the authority of a key to someone who does an HTTPS transaction with
the relevant server.  The fact that the server needs to be reachable and
responsive at the time the JWT is being validated is a serious limitation in
some use cases, two examples of which are given below.

In this document, we define "Signed JWK Sets", a format for a redistributable
proof of authority for an issuer key.  As in OIDC and SD-JWT-VC, we assume that
issuers are identified by HTTPS URLs, or at least by domain names.  A signed
issuer key is then simply a JWT whose payload contains the issuer key in
question, and whose header contains an X.509 certificate proving that the
JWT-signing key is authoritative for the issuer's domain name.

This design preserves the same trust model as in the HTTPS-based proof of
authority; it just swaps the signature in the TLS handshake underlying HTTPS for
an object signature.  Signed issuer keys are thus "redistributable" in the same
sense that an intermediate certificate would be, so that they can be verified
without the issuer being online and reachable.

We also define a simple syntax for referencing signed issuer keys in metadata
documents such as OIDC Discovery metadata and SD-JWT-VC issuer metadata.

## Use Case: End-to-End Security

In applications using MLS for end-to-end security, endpoints can authenticate to
each other using Verifiable Credentials (VCs) {{?I-D.barnes-mls-addl-creds}}.
These VCs are formatted as JWTs.  In such applications, HTTPS-based proof of
authority is an availability risk to the application and to the VC issuer.

The risk to the application is clear: A client joining an MLS group needs to
validate the credentials of their peers.  If part of that process entails making
an HTTPS query to validate the authority of the keys used to sign their peers'
credentials, and the relevant HTTPS server is down, then the client will not be
able to join the group and use the application.  Worse, since different peers
may have credentials from different issuers, an outage at any one of those
issuers can cause downtime for the application.

The use of HTTPS to validate authority also creates unnecessary load on the VC
issuer.  Consider, for example, an MLS-based video conference with 1,000
participants presenting credentials from 10 different issuers, all of whom join
at the start of the meeting.  This situation would create a spike of around
10,000 HTTPS requests to the VC issuer.

With signed issuer keys, the clients in a meeting can bundle the proof of
authority along with their VC, avoiding the need for any HTTPS interaction with
the issuer at all.

## Use Case: Verifying Stored Signatures

Some applications are interested in verifying historical signatures.  For
example, a container registry might wish to demonstrate that a container was
signed by its author at some time in the past.

Live HTTPS-based proofs of authority are fundamentally incompatible with these
applications, since the proof of authority they produce cannot be preserved and
reused later.  With signed issuer keys, a trusted timestamping authority is all
that is needed to achieve the desired properties.

Suppose the registry stores the following information for each container:

* A signature by the container author over the container
* A JWT attesting to the container author's identity and public key, e.g., a
  Verifiable Credential or an OpenPubkey PK Token {{OpenPubkey}}
* A Signed JWK Set providing the JWT issuer's key and proving its authority
  for the issuer
* An assertion by the timestamping authority that all of the above artifacts
  existed at a time in the past when they were all valid

Based on the timetamping authority's assertion, a relying party can validate
that at the specified time, the container was signed by an author with the
specified identity, and that the identity was asserted by the specified issuer.

## Alternatives

An alternative design discussed in {{Section 3.5 of ?I-D.ietf-oauth-sd-jwt-vc}}
is to simply sign the based JWT with an X.509 certified keys.  This design has a
few drawbacks relative to the design described here:

First, it changes the trust model relative to HTTPS-based proof of authority.
The issuer JWT-signing key is removed as an intermediate step.  This makes it
more difficult for this design to coexist with HTTPS-based proof of identity.

Second, it removes flexibility that allows for efficiency.  The extra data of
the X.509 certificate chain has to be sent every time the base JWT is sent.
Allowing the two to be decoupled allows for more flexible caching schemes.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# JWK Lifetimes

JWT issuers typically rotate their keys, so that each issuer key is only used to
sign JWTs for a specific period of time.  Making this window known to Relying
Parties can allow them guard against compromise of retired keys.  If a Relying
Party has a trustworthy signal of when a JWT was issued (e.g., from a timestamp
authority), and the Relying Party knows when the Issuer was using the key that
signed the JWT, then the Relying Party can enforce that JWT signing time is
within the key usage window.

To communicate this window, this document defines `nbf` and `exp` fields for
JWKs with semantics analogous to the corresponding JWT claims.  

## "nbf" (Not Before) Parameter 

The `nbf` (not before) parameter identifies the time at which the holder of this
key began using it.  When used with signature keys, relying parties MUST reject
an object signed by this key if the object was signed before the time indicated
in the `nbf` parameter.  Implementers MAY provide for some small leeway, usually
no more than a few minutes, to account for clock skew.  Its value MUST be a
number containing a NumericDate value.  Use of this parameter is OPTIONAL.

## "exp" (Expiration Time) Parameter

The `exp` (expiration time) parameter identifies the time at which the holder of
this key stopped using it.  When used with signature keys, relying parties MUST
reject an object signed by this key if the object was signed after the time
indicated in the `exp` parameter. Implementers MAY provide for some small
leeway, usually no more than a few minutes, to account for clock skew.  Its
value MUST be a number containing a NumericDate value.  Use of this parameter is
OPTIONAL.


# Signed JWK Set Format

A Signed JWK Set for a JWT issuer MUST meet the following requirements:

* The Signed JWK Set MUST be structured as a JWT {{!RFC7519}} and generally meet
  the requirements of that specification.

* The `x5c` field of the Signed JWK Set MUST be populated with a certificate
  chain that authenticates the domain name in the `iss` field.  The domain name
  MUST appear as a `dNSName` entry in the `subjectAltName` extension of the
  end-entity certificate.

* The `alg` field of the Signed JWK Set MUST represent an algorithm that is
  compatible with the subject public key of the certificate in the `x5c`
  parameter.

* The Signed JWK Set MUST contain an `iss` claim.  The value of the `iss` claim
  MUST be the `iss` value that the issuer uses in JWTs that it issues.  This
  value MUST be either a domain name or an HTTPS URL.

* The Signed JWK Set MUST contain a `nbf` and `exp` claims.

* The Signed JWK Set MUST contain a `jwks` claim, whose value is the issuer's
  JWK Set.

* The JWKs in the `jwks` JWK Set SHOULD contain `nbf` and `exp` fields, as
  described in {{jwk-lifetimes}}.

* The Signed JWK Set SHOULD NOT contain an `aud` claim.

{{fig-example-jwks}} shows the contents of the JWT header and JWT payload for an example Signed JWK Set, omitting the full certificate chain:

~~~
JWT Header:
{
  "alg": "ES256",
  "typ": "JWT",
  "x5c": ["MII..."]
}

JWT Payload:
{
  "iat": 1667575982,
  "exp": 1668180782,
  "iss": "https://server.example.com",
  "jwks": {
    "keys": [{
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "nbf": 1710362112,
      "exp": 1718325296,
      "kid": "XTSGmh734_J6fOWUbI7BNim7wyvj5LWx8GzuIH7WHw8",
      "x": "qiGKLwXRJmJR_AOQpWOHXLX5uYIfzvPwDurWvmZBwvw",
      "y": "ip8nyuLpJ5NpriZzCVKiG0TteqPMkrzfNOUQ8YzeGdk"
    }]
  }
}

JWS Signature:
// 
~~~
{: #fig-example-jwks title="A Signed JWK Set" }

A Verifier that receives such a signed JWK Set validates it by taking the
following steps:

1. If this Signed JWK Set was looked up using an `iss` value, verify that the
   value of the `iss` claim in the Signed JWK Set is identical to the one used
   to discover it.

1. Verify that the JWT is currently valid, according to its `nbf` and `exp` claims.

1. Verify that the certificate chain in the `x5c` field is currently valid from a trusted
   certificate authority (see [@!RFC5280][@!RFC6125]).

1. Verify that the end-entity certificate matches the `iss` field of the Signed
   JWK Set.

1. Verify the signature on the JWS using the subject public key of the
   end-entity certificate

# Referencing Signed JWK Sets

JWT issuers commonly advertise their JWK Sets using mechanisms such as OpenID
Connect Discovery or SD-JWT-VC Credential Issuer Metadata {{OIDC-Discovery}}
{{I-D.ietf-oauth-sd-jwt-vc}}.  These discovery mechanisms could be extended to
also provide Signed JWK Sets, using one of a few approaches.

Current discovery mechanisms typically present the issuer's JWK set as a value
or link embedded in the metadata object.  One could define parallel fields in a
metadata object to reference a provider's current Signed JWK Set:

~~~ json
{
    // Other metadata...

    // Current mechanisms for unsigned JWKS
    "jwks_uri": "https://example.com/jwks",
    "jwks": { "keys": [ ... ] },

    // New mechanisms for Signed JWK Sets
    "signed_jwks_uri": "https://example.com/signed_jwks",
    "signed_jwks": "eyJ...",
}
~~~
{: fig-issuer-metadata title="Referencing a Signed JWK Set like a JWK Set"}

Such a mechanism requires the issuer to list all of the keys that are currently
valid in one Signed JWK Set, requiring a Relying Party to download the whole
Signed JWK Set even if they are only interested in one key.

An alternative design would allow for more specific Signed JWK Sets, covering
individual keys and referencing them by `kid`.  With such a design, an issuer
metadata object would contain a map like the following (showing three keys with
`kid` values "us-east-2024-01", "us-west-2024-01", and "us-east-2024-04"):

~~~ json
{
    // Other metadata...

    "signed_jwks": {
        "us-east-2024-01": "https://example.com/signed_jwks/us-east-2024-01",
        "us-west-2024-01": "https://example.com/signed_jwks/us-east-2024-01",
        "us-east-2024-04": "https://example.com/signed_jwks/us-east-2024-01",
    }
}
~~~
{: fig-issuer-metadata title="Referencing individual Signed JWK Sets by Key ID"}

# Security Considerations

[[ TODO - Security; lifetimes, revocation ]]


# IANA Considerations

[[ TODO: Register `nbf` and `exp` as JWK fields ]]


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.


