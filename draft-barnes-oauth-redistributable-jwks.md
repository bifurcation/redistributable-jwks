---
title: "Redistributable JWK Sets"
abbrev: "Redistributable JWKS"
category: info

docname: draft-barnes-oauth-redistributable-jwks-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
 -
    fullname: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    fullname: Sharon Goldberg
    organization: BastionZero
    email: goldbe@bastionzero.com

normative:

informative:


--- abstract

A relying party verifying a JSON Web Token (JWT) needs to verify that the public key
used to verify the signature legitimately represents the issuer represented in the
"iss" claim of the JWT.  Today, relying parties commonly use the "iss" claim to
fetch a set of authorized signing keys over HTTPS, relying on the security of HTTPS
to establish the authority of the downloaded keys for that issuer.  The ephemerality
of this proof of authority makes it unsuitable for certain use cases.  In this document,
we define a format for signed issuer keys, which establish the authority of a key
using a signed object instead of an HTTPS connection.

--- middle

# Introduction

A relying party verifying a JSON Web Token (JWT) {{!RFC7519}} needs to verify that the 
public key used to verify the signature legitimately represents the issuer represented in the
"iss" claim of the JWT.

Today, relying parties commonly use the `iss` claim to fetch a set of authorized signing 
keys over HTTPS, relying on the security of HTTPS to establish the authority of the downloaded
keys for that issuer.  For example, in OpenID Connect Discovery {{?OIDC-Discovery}}, the `iss` claim
is used to form a URL from which issuer metadata is downloaded over HTTPS.  The issuer's JWK set is
linked via the `jwks_uri` field in the metadata.  The SD-JWT-VC specification describes a similar
HTTPS-based mechanism for discovering the valid keys for an issuer (see {{Section 5 of ?I-D.ietf-oauth-sd-jwt-vc-}}).

These HTTPS-based authority mechanisms are "live", in the sense that they can only prove the authority
of a key to someone who does an HTTPS transaction with the relevant server.  The fact that the server
needs to be reachable and responsive at the time the JWT is being validated is a serious limitation
in some use cases, two examples of which are given below.

In this document, we define "signed issuer keys", a format for a redistributable proof of authority
for an issuer key.  As in OIDC and SD-JWT-VC, we assume that issuers are identified by HTTPS URLs, or at
least by domain names.  A signed issuer key is then simply a JWT whose payload contains the issuer key
in question, and whose header contains an X.509 certificate proving that the JWT-signing key is authoritative
for the issuer's domain name.

This design preserves the same trust model as in the HTTPS-based proof of authority; it just swaps the signature 
in the TLS handshake underlying HTTPS for an object signature.  Signed issuer keys are thus "redistributable"
in the same sense that an intermediate certificate would be, so that they can be verified without the issuer 
being online and reachable.

We also define a simple syntax for referencing signed issuer keys in metadata documents such as OIDC Discovery
metadata and SD-JWT-VC issuer metadata.

## Use Case: End-to-End Security

[[ Context: Messaging/meeting + VC/MLS. Need redistributability to deal with availability concerns ]]

## Use Case: Verifying Stored Signatures

[[ Context: Long-term storage ~ timestamping authority.  E.g., container registries  Need redistributability to prove authority when verifying in the future ]]

## Alternatives

[[ Just put X5C in the base JWT ~ change to trust model, bloat in base JWTs ]]

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Signed Issuer Keys

[[ JWT with X5C ]]

# Referencing Signed Issuer Keys

[[ { kid: url } ]]

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
