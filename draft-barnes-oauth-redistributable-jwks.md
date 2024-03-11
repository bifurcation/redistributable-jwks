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
  OIDC-Discovery:
    target: https://openid.net/specs/openid-connect-discovery-1_0.html
    title: "OpenID Connect Discovery 1.0 incorporating errata set 2"
    date: 2023-12-15
  OpenPubKey:
    target: https://www.bastionzero.com/openpubkey
    title: "OpenPubkey"

--- abstract

A relying party verifying a JSON Web Token (JWT) needs to verify that the public
key used to verify the signature legitimately represents the issuer represented
in the "iss" claim of the JWT.  Today, relying parties commonly use the "iss"
claim to fetch a set of authorized signing keys over HTTPS, relying on the
security of HTTPS to establish the authority of the downloaded keys for that
issuer.  The ephemerality of this proof of authority makes it unsuitable for
certain use cases.  In this document, we define a format for signed issuer keys,
which establish the authority of a key using a signed object instead of an HTTPS
connection.

--- middle

# Introduction

A relying party verifying a JSON Web Token (JWT) {{!RFC7519}} needs to verify
that the public key used to verify the signature legitimately represents the
issuer represented in the "iss" claim of the JWT.

Today, relying parties commonly use the `iss` claim to fetch a set of authorized
signing keys over HTTPS, relying on the security of HTTPS to establish the
authority of the downloaded keys for that issuer.  For example, in OpenID
Connect Discovery {{?OIDC-Discovery}}, the `iss` claim is used to form a URL
from which issuer metadata is downloaded over HTTPS.  The issuer's JWK set is
linked via the `jwks_uri` field in the metadata.  The SD-JWT-VC specification
describes a similar HTTPS-based mechanism for discovering the valid keys for an
issuer (see {{Section 5 of ?I-D.ietf-oauth-sd-jwt-vc}}).

These HTTPS-based authority mechanisms are "live", in the sense that they can
only prove the authority of a key to someone who does an HTTPS transaction with
the relevant server.  The fact that the server needs to be reachable and
responsive at the time the JWT is being validated is a serious limitation in
some use cases, two examples of which are given below.

In this document, we define "signed issuer keys", a format for a redistributable
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
at the start of the meeting.  This situation would create a spike of 10,000
HTTPS requests to the VC issuer.

With signed issuer keys, the clients in a meeting can bundle the proof of
authority along with their VC, avoiding the need for any HTTPS interaction with
the issuer at all.

## Use Case: Verifying Stored Signatures

Some applications are interested in verifying historical signatures.  For
example, a container registry might wish to demonstrate that a container was
signed by its author a some time in the past.  

Live HTTPS-based proofs of authority are fundamentally incompatible with these
applications, since the proof of authority they produce cannot be preserved and
reused later.  With signed issuer keys, a trusted timestamping authority is all
that is needed to achieve the desired properties.

Suppose the registry stores the following information for each container:

* A signature by the container author over the container
* A JWT attesting to the container author's identity and public key, e.g., a
  Verifiable Credential or an OpenPubKey PKToken {{?OpenPubkey}}
* A signed issuer key providing the JWT issuer's key and proving its authority
  for the issuer
* An assertion by the timestamping authority that all of the above artifacts
  existed at a time in the past when they were all valid

Based on the timetamping authority's assertion, a relying party can validate
that at the specified time, the container was signed by an author with the
specified identity, and that the identity was asserted by the specified issuer.

## Alternatives

An alternative design discussed in {{Section 3.5 of ?I-D.ietf-oauth-sd-jwt-vc}}
is to simply sign the based JWT with an X.509 certified keys.  This design has a
few drawbacks relative to the signed issuer key design described here:

First, it changes the trust model relative to HTTPS-based proof of authority.
The issuer JWT-signing key is removed as an intermediate step.  This makes it
more difficult for this design to coexist with HTTPS-based proof of identity.

Second, it removes flexibility that allows for efficiency.  The extra data of
the X.509 certificate chain has to be sent every time the base JWT is sent.
Allowing the two to be decoupled allows for more flexible caching schemes.

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


