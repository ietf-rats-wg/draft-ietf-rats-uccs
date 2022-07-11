---
v: 3

title: A CBOR Tag for Unprotected CWT Claims Sets
abbrev: Unprotected CWT Claims Sets
docname: draft-ietf-rats-uccs-latest
area: Security
wg: RATS Working Group
kw: Internet-Draft
cat: std
consensus: true
stream: IETF

venue:
  group: Remote ATtestation ProcedureS (rats)
  mail: rats@ietf.org
  github: ietf-rats-wg/draft-ietf-rats-uccs

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: J. O'Donoghue
  name: Jeremy O'Donoghue
  org: Qualcomm Technologies Inc.
  abbrev: Qualcomm Technologies Inc.
  email: jodonogh@qti.qualcomm.com
  street: 279 Farnborough Road
  code: "GU14 7LS"
  city: Farnborough
  country:  United Kingdom
- ins: N. Cam-Winget
  name: Nancy Cam-Winget
  org: Cisco Systems
  email: ncamwing@cisco.com
  street: 3550 Cisco Way
  code: '95134'
  city: San Jose
  region: CA
  country: USA
-
  name: Carsten Bormann
  org: Universität Bremen TZI
  street: Postfach 330440
  city: Bremen
  code: D-28359
  country: Germany
  phone: +49-421-218-63921
  email: cabo@tzi.org

normative:
  RFC8949: cbor
  RFC8152: cose
  RFC7519: jwt
  RFC8725: jwtbcp
  RFC8392: cwt
  IANA.cbor-tags: tags

informative:
  RFC8446: tls
  I-D.ietf-rats-architecture: rats
  I-D.ietf-teep-architecture: teep
  TPM2:
    title: >
      Trusted Platform Module Library Specification, Family “2.0”, Level 00, Revision 01.59 ed.,
      Trusted Computing Group
    date: 2019
  I-D.ietf-rats-eat: eat
  I-D.ietf-cose-rfc8152bis-struct: cose-new-struct
  I-D.ietf-cose-rfc8152bis-algs: cose-new-algs
  RFC8747: cnf
  RFC8693: tokex
  RFC6749: scope

--- abstract

CBOR Web Token (CWT, RFC 8392) Claims Sets sometimes do not need the
protection afforded by wrapping them into COSE, as is required for a true
CWT.  This specification defines a CBOR tag for such unprotected CWT
Claims Sets (UCCS) and discusses conditions for its proper use.


[^status]

[^status]:
    The present version (-02) has a new appendix with CDDL.

--- middle

# Introduction

A CBOR Web Token (CWT) as specified by {{-cwt}} is always wrapped in a
CBOR Object Signing and Encryption (COSE, {{-cose}}) envelope.
COSE provides -- amongst other things -- the end-to-end data origin
authentication and integrity protection employed by RFC 8392 and
optional encryption for CWTs.
Under the right circumstances ({{secchan}}),
though, a signature providing proof for authenticity and integrity can be
provided through the transfer protocol and thus omitted from the
information in a CWT without compromising the intended goal of authenticity
and integrity.
In other words, if communicating parties have a pre-existing security
association they can reuse it to provide authenticity and integrity
for their messages, enabling the basic principle of using resources
parsimoniously.
Specifically, if a mutually Secured Channel is established between two
remote peers, and if that Secure Channel provides the required
properties (as discussed below), it is possible to omit the protection
provided by COSE, creating a use case for unprotected CWT Claims Sets.
Similarly, if there is one-way authentication, the party that did not
authenticate may be in a position to send authentication information through
this channel that allows the already authenticated party to authenticate the
other party.

This specification allocates a CBOR tag to mark Unprotected CWT Claims Sets
(UCCS) as such and discusses conditions for its proper use in the scope of
Remote ATtestation procedureS (RATS) and the conveyance of Evidence from an
Attester to a Verifier.

This specification does not change {{-cwt}}: A true CWT does not make use of
the tag allocated here; the UCCS tag is an alternative to using COSE
protection and a CWT tag.
Consequently, within the well-defined scope of a secured channel, it
can be acceptable and economic to use the contents of a CWT without
its COSE container and tag it with a UCCS CBOR tag for further
processing within that scope -- or to use the contents of a UCCS CBOR
tag for building a CWT to be signed by some entity that can vouch for
those contents.

## Terminology

The term Claim is used as in {{-jwt}}.

The terms Claim Key, Claim Value, and CWT Claims Set are used as in
{{-cwt}}.

The terms Attester, Attesting Environment and Verifier are used as in {{-rats}}.

UCCS:
: Unprotected CWT Claims Set(s); CBOR map(s) of Claims as defined by the CWT
Claims Registry that are composed of pairs of Claim Keys and Claim Values.

Secure Channel:
: A protected communication channel between two peers that can ensure the same qualities
associated for UCCS conveyance as CWT conveyance without any additional protection.

All terms referenced or defined in this section are capitalized in the remainder of
this document.

{::boilerplate bcp14-tagged}

# Example Use Cases

Use cases involving the conveyance of Claims, in particular, remote attestation procedures (RATS, see
{{-rats}}) require a standardized data definition and encoding format that can be transferred
and transported using different communication channels.  As these are Claims, {{-cwt}} is
a suitable format. However, the way these Claims are secured depends on the deployment, the security
capabilities of the device, as well as their software stack.  For example, a Claim may be securely
stored and conveyed using a device's Trusted Execution Environment (TEE, see {{-teep}}) or especially in some
resource constrained environments, the same process that provides the secure communication
transport is also the delegate to compose the Claim to be conveyed.  Whether it is a transfer
or transport, a Secure Channel is presumed to be used for conveying such UCCS.  The following sections
further describe the RATS usage scenario and corresponding requirements for UCCS deployment.

# Characteristics of a Secure Channel {#secchan}

A Secure Channel for the conveyance of UCCS needs to provide the security
properties that would otherwise be provided by COSE for a CWT.
In this regard, UCCS is similar in security considerations to JWTs {{-jwtbcp}}
using the algorithm "none".  RFC 8725 states:

{:quote}
> \[...] if a JWT is cryptographically
protected end-to-end by a transport layer, such as TLS using
cryptographically current algorithms, there may be no need to apply another
layer of cryptographic protections to the JWT.  In such cases, the use of
the "none" algorithm can be perfectly acceptable.

The security considerations discussed, e.g., in {{Sections 2.1, 3.1,
and 3.2 of -jwtbcp}} apply in an analogous way to the use of UCCS as
elaborated on in this document.

Secure Channels are often set up in a handshake protocol that mutually
derives a session key, where the handshake protocol establishes the
(identity and thus) authenticity of one or both ends of the communication.
The session key can
then be used to provide confidentiality and integrity of the transfer of
information inside the Secure Channel.  A well-known example of a such a
Secure Channel setup protocol is the TLS {{-tls}} handshake; the
TLS record protocol can then be used for secure conveyance.

As UCCS were initially created for use in Remote ATtestation procedureS
(RATS) Secure Channels, the following subsection provides a discussion of
their use in these channels.  Where other environments are intended to be
used to convey UCCS, similar considerations need to be documented before
UCCS can be used.

## UCCS and Remote ATtestation procedureS (RATS)

For the purposes of this section, the Verifier is the receiver of the UCCS
and the Attester is the provider of the UCCS.

Secure Channels can be transient in nature. For the purposes of this
specification, the mechanisms used to establish a Secure Channel are out of
scope.

As a minimum requirement in the scope of RATS Claims, the Verifier MUST
authenticate the Attester as part of the establishment of the Secure Channel.
Furthermore, the channel MUST provide integrity of the communication from the
Attester to the Verifier.
If confidentiality is also required, the receiving side needs to be
authenticated as well; this can be achieved if the Verifier and the Attester
mutually authenticate when establishing the Secure Channel.

The extent to which a Secure Channel can provide assurances that UCCS
originate from a trustworthy attesting environment depends on the
characteristics of both the cryptographic mechanisms used to establish the
channel and the characteristics of the attesting environment itself.

A Secure Channel established or maintained using weak cryptography
may not provide the assurance required by a relying party of the authenticity
and integrity of the UCCS.

Ultimately, it is up to the Verifier's policy to determine whether to accept
a UCCS from the Attester and to the type of Secure Channel it must negotiate.
While the security considerations of the cryptographic algorithms used are similar
to COSE, the considerations of the secure channel should also adhere to the policy
configured at each of the Attester and the Verifier.  However, the policy controls
and definitions are out of scope for this document.

Where the security assurance required of an attesting environment by a
relying party requires it, the attesting environment may be implemented
using techniques designed to provide enhanced protection from an attacker
wishing to tamper with or forge UCCS.  A possible approach might be to
implement the attesting environment in a hardened environment such as a
TEE {{-teep}} or a TPM {{TPM2}}.

When UCCS emerge from the Secure Channel and into the Verifier, the security
properties of the Secure Channel no longer apply and UCCS have the same properties
as any other unprotected data in the Verifier environment.
If the Verifier subsequently forwards UCCS, they are treated as though they originated within the Verifier.

As with EATs nested in other EATs ({{Section 3.20.1.2 of -eat}}), the Secure
Channel does not endorse fully formed CWTs transferred through it.
Effectively, the COSE envelope of a CWT shields the CWT Claims Set from the
endorsement of the Secure Channel.  (Note that EAT might add a nested UCCS
Claim, and this statement does not apply to UCCS nested into UCCS, only to
fully formed CWTs)

## Privacy Preserving Channels

A Secure Channel which preserves the privacy of the Attester may provide
security properties equivalent to COSE, but only inside the life-span of the
session established.  In general, a Verifier cannot correlate UCCS received
in different sessions from the same attesting environment based on the
cryptographic mechanisms used when a privacy preserving Secure Channel is
employed.

In the case of a Remote Attestation, the attester must consider whether any UCCS it returns over a privacy
preserving Secure Channel compromises the privacy in unacceptable ways.  As
an example, the use of the EAT UEID {{-eat}} Claim in UCCS over a privacy
preserving Secure Channel allows a verifier to correlate UCCS from a single
attesting environment across many Secure Channel sessions. This may be
acceptable in some use-cases (e.g. if the attesting environment is a
physical sensor in a factory) and unacceptable in others (e.g. if the
attesting environment is a device belonging to a child).

# IANA Considerations

In the registry {{-tags}},
IANA is requested to allocate the tag in {{tab-tag-values}} from the
FCFS space, with the present document as the specification reference.

| Tag    | Data Item | Semantics                             |
| TBD601 | map       | Unprotected CWT Claims Set \[RFCthis] |
{: #tab-tag-values cols='r l l' title="Values for Tags"}


# Security Considerations

The security considerations of {{-cbor}} apply.
The security considerations of {{-cwt}} need to be applied analogously,
replacing the role of COSE with that of the Secured Channel.

{{secchan}} discusses security considerations for Secure Channels, in which
UCCS might be used.
This document provides the CBOR tag definition for UCCS and a discussion
on security consideration for the use of UCCS in
Remote ATtestation procedureS (RATS).  Uses of UCCS outside the scope of
RATS are not covered by this document.  The UCCS specification - and the
use of the UCCS CBOR tag, correspondingly - is not intended for use in a
scope where a scope-specific security consideration discussion has not
been conducted, vetted and approved for that use.

## General Considerations

Implementations of Secure Channels are often separate from the application
logic that has security requirements on them.  Similar security
considerations to those described in {{-cose-new-struct}} for obtaining the
required levels of assurance include:

* Implementations need to provide sufficient protection for private or
  secret key material used to establish or protect the Secure Channel.
* Using a key for more than one algorithm can leak information about the
  key and is not recommended.
* An algorithm used to establish or protect the Secure Channel may have
  limits on the number of times that a key can be used without leaking
  information about the key.

The Verifier needs to ensure that the management of key material used
establish or protect the Secure Channel is acceptable. This may include
factors such as:

* Ensuring that any permissions associated with key ownership are respected
  in the establishment of the Secure Channel.
* Cryptographic algorithms are used appropriately.
* Key material is used in accordance with any usage restrictions such as
  freshness or algorithm restrictions.
* Ensuring that appropriate protections are in place to address potential
  traffic analysis attacks.

## AES-CBC_MAC

* A given key should only be used for messages of fixed or known length.
* Different keys should be used for authentication and encryption operations.
* A mechanism to ensure that IV cannot be modified is required.

{{Section 3.2.1 of -cose-new-algs}} contains a detailed explanation of these considerations.

## AES-GCM

* The key and nonce pair are unique for every encrypted message.
* The maximum number of messages to be encrypted for a given key is not exceeded.

{{Section 4.1.1 of -cose-new-algs}} contains a detailed explanation of these considerations.

## AES-CCM

* The key and nonce pair are unique for every encrypted message.
* The maximum number of messages to be encrypted for a given block cipher is not exceeded.
* The number of messages both successfully and unsuccessfully decrypted is used to
  determine when rekeying is required.

{{Section 4.2.1 of -cose-new-algs}} contains a detailed explanation of these considerations.

## ChaCha20 and Poly1305

* The nonce is unique for every encrypted message.
* The number of messages both successfully and unsuccessfully decrypted is used to
  determine when rekeying is required.

{{Section 4.3.1 of -cose-new-algs}} contains a detailed explanation of these considerations.

--- back

# CDDL

{{-cwt}} does not define CDDL for CWT Claims sets.

This specification proposes using the definitions in {{fig-claims-set}}
for the claims set defined in {{-cwt}}.  Note that these definitions
have been built such that they also can describe {{-jwt}} claims sets by
disabling feature "cbor" and enabling feature "json", but this
flexibility is not the subject of the present specification.

~~~ cddl
Claims-Set = {
 * $$Claims-Set-Claims
 * Claim-Label .feature "extended-claims-label" => any
}
Claim-Label = int / text
string-or-uri = text

$$Claims-Set-Claims //= ( iss-claim-label => string-or-uri  )
$$Claims-Set-Claims //= ( sub-claim-label => string-or-uri  )
$$Claims-Set-Claims //= ( aud-claim-label => string-or-uri  )
$$Claims-Set-Claims //= ( exp-claim-label => ~time )
$$Claims-Set-Claims //= ( nbf-claim-label => ~time )
$$Claims-Set-Claims //= ( iat-claim-label => ~time )
$$Claims-Set-Claims //= ( cti-claim-label => bytes )

iss-claim-label = JC<"iss", 1>
sub-claim-label = JC<"sub", 2>
aud-claim-label = JC<"aud", 3>
exp-claim-label = JC<"exp", 4>
nbf-claim-label = JC<"nbf", 5>
iat-claim-label = JC<"iat", 6>
cti-claim-label = CBOR-ONLY<7>  ; jti in JWT: different name and text

JSON-ONLY<J> = J .feature "json"
CBOR-ONLY<C> = C .feature "cbor"
JC<J,C> = JSON-ONLY<J> / CBOR-ONLY<C>
~~~
{: #fig-claims-set title="CDDL definition for Claims-Set"}

Specifications that define additional claims should also supply
additions to the $$Claims-Set-Claims socket, e.g.:

~~~ cddl
; [RFC8747]
$$Claims-Set-Claims //= ( 8: CWT-cnf ) ; cnf
CWT-cnf = {
  (1: CWT-COSE-Key) //
  (2: CWT-Encrypted_COSE_Key) //
  (3: CWT-kid)
}

CWT-COSE-Key = COSE_Key
CWT-Encrypted_COSE_Key = COSE_Encrypt / COSE_Encrypt0
CWT-kid = bytes

; [RFC8693]
$$Claims-Set-Claims //= ( 9: CWT-scope ) ; scope
; TO DO: understand what this means:
; scope The scope of an access token as defined in [RFC6749].
; scope 9 byte string or text string [IESG] [RFC8693, Section 4.2]
CWT-scope = bytes / text

; [RFC-ietf-ace-oauth-authz-45, Section 5.10]
$$Claims-Set-Claims //= ( 38: CWT-ace-profile ) ; ace_profile
CWT-ace-profile = $CWT-ACE-Profiles /
  int .feature "ace_profile-extend"
; fill in from IANA registry
;   https://www.iana.org/assignments/ace/ace.xhtml#ace-profiles :
$CWT-ACE-Profiles /= 1 ; coap_dtls

$$Claims-Set-Claims //= ( 39: CWT-cnonce ) ; cnonce
CWT-cnonce = bytes

$$Claims-Set-Claims //= ( 40: CWT-exi ) ; exi
CWT-exi = uint ; in seconds (5.10.3)

;;; insert CDDL from 9052-to-be to complete these CDDL definitions.

~~~



# Example

The example CWT Claims Set from {{Appendix A.1 of -cwt}} can be turned into
an UCCS by enclosing it with a tag number TBD601:

~~~~
 <TBD601>(
   {
     / iss / 1: "coap://as.example.com",
     / sub / 2: "erikw",
     / aud / 3: "coap://light.example.com",
     / exp / 4: 1444064944,
     / nbf / 5: 1443944944,
     / iat / 6: 1443944944,
     / cti / 7: h'0b71'
   }
 )
~~~~

<!--  LocalWords:  Attester Verifier UCCS decrypted rekeying JWT EATs
 -->
<!--  LocalWords:  Verifier's CWTs attester verifier FCFS
 -->

--- back

Acknowledgements
================
{:unnumbered}

{{{Laurence Lundblade}}} suggested some improvements to the CDDL.
