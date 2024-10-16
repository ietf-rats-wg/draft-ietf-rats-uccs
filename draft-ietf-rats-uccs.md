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
  group: Remote ATtestation procedureS (rats)
  mail: rats@ietf.org
  github: ietf-rats-wg/draft-ietf-rats-uccs

author:
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@ietf.contact
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
  STD94: cbor
# RFC8949
  RFC7519: jwt
  BCP225: jwtbcp
# RFC8725
  RFC8392: cwt
  IANA.cbor-tags: tags
  IANA.cwt:
  RFC8610: cddl
  RFC9165: control1

informative:
  IANA.media-types:
  IANA.core-parameters:
  RFC4949: sec-glossary
  RFC8446: tls
  RFC9334: rats
  RFC9397: teep
  TPM2:
    title: >
      Trusted Platform Module Library Specification, Family “2.0”, Level 00, Revision 01.59 ed.,
      Trusted Computing Group
    date: 2019
  I-D.ietf-rats-eat: eat
  STD96: cose
# RFC9052
  RFC9053: cose-new-algs
  RFC8747: cnf        # used in CDDL only
  NIST-SP800-90Ar1: DOI.10.6028/NIST.SP.800-90Ar1

entity:
  SELF: RFCthis

--- abstract

When transported over secure channels, CBOR Web Token (CWT, RFC 8392) Claims Sets may not need the protection afforded by wrapping them into COSE, as is required for an actual RFC 8392 CWT.
This specification defines a CBOR tag for such unprotected CWT Claims Sets (UCCS) and discusses conditions for its proper use.

<!--
[^status]

[^status]:
    The present version (-03)
 -->

--- middle

# Introduction

A CBOR Web Token (CWT) as specified by {{-cwt}} is always wrapped in a
CBOR Object Signing and Encryption (COSE, {{-cose}}) envelope.
COSE provides -- among other things -- end-to-end data origin
authentication and integrity protection employed by RFC 8392 as well as
optional encryption for CWTs.
Under the right circumstances ({{secchan}}),
though, a signature providing proof for authenticity and integrity can be
provided through the transfer protocol and thus omitted from the
information in a CWT without compromising the intended goal of authenticity
and integrity.
In other words, if communicating parties have a preexisting security
association, they can reuse it to provide authenticity and integrity
for their messages, enabling the basic principle of using resources
parsimoniously.
Specifically, if a mutually secured channel is established between two
remote peers, and if that secure channel provides the required
properties (as discussed below), it is possible to omit the protection
provided by COSE, creating a use case for unprotected CWT Claims Sets.
Similarly, if there is one-way authentication, the party that did not
authenticate may be in a position to send authentication information through
this channel that allows the already authenticated party to authenticate the
other party; this effectively turns the channel into a mutually
secured channel.

This specification allocates a CBOR tag to mark Unprotected CWT Claims Sets
(UCCS) as such and discusses conditions for its proper use in the scope of
Remote Attestation Procedures (RATS {{-rats}}) for the
conveyance of RATS Conceptual Messages.

This specification does not change {{-cwt}}: An actual RFC 8392 CWT does not make use of
the tag allocated here; the UCCS tag is an alternative to using COSE
protection and a CWT tag.
Consequently, within the well-defined scope of a secure channel, it
can be acceptable and economic to use the contents of a CWT without
its COSE container and tag it with a UCCS CBOR tag for further
processing within that scope -- or to use the contents of a UCCS CBOR
tag for building a CWT to be signed by some entity that can vouch for
those contents.

## Terminology

The term Claim is used as in {{-jwt}}.

The terms Claim Key, Claim Value, and CWT Claims Set are used as in
{{-cwt}}.

The terms Attester, Attesting Environment, Evidence, Relying Party and Verifier are used as in {{-rats}}.

UCCS:
: Unprotected CWT Claims Set(s); CBOR map(s) of Claims as defined by the CWT
Claims Registry that are composed of pairs of Claim Keys and Claim Values.

Secure Channel:
: {{NIST-SP800-90Ar1}} defines a Secure Channel as follows:

  {:aside}
  > <!-- This really is a block quote, but RFCXMLv3 doesn't allow that -->
  "A path for transferring data between two entities or components that
  ensures confidentiality, integrity and replay protection, as well as
  mutual authentication between the entities or components. The secure
  channel may be provided using approved cryptographic, physical or
  procedural methods, or a combination thereof."

  For the purposes of the present document, we focus on a protected communication
  channel used for conveyance that can ensure the same qualities as CWT without
  having the COSE protection available: mutual authentication,
  integrity protection, confidentiality.
  (Replay protection can be added by including a nonce claim such as
  Nonce (claim 10 {{IANA.cwt}}).)
  Examples include conveyance via PCIe
  (Peripheral Component Interconnect Express) IDE (Integrity and Data
  Encryption) or a TLS tunnel.

All terms referenced or defined in this section are capitalized in the remainder of
this document.

{::boilerplate bcp14-tagged-bcp14}

# Deployment and Usage of UCCS

Usage scenarios involving the conveyance of Claims, in particular
RATS, require a standardized data definition and encoding format that
can be transferred
and transported using different communication channels.  As these are
Claims, the Claims Sets defined in {{-cwt}} are
a suitable format.  However, the way these Claims are secured depends on the deployment, the security
capabilities of the device, as well as their software stack.  For example, a Claim may be securely
stored and conveyed using a device's Trusted Execution Environment (TEE, see {{-teep}}) or
a Trusted Platform Module (TPM, see {{TPM2}}).
Especially in some resource-constrained environments, the same process that provides the secure communication
transport is also the delegate to compose the Claim to be conveyed.  Whether it is a transfer
or transport, a Secure Channel is presumed to be used for conveying such UCCS.  The following sections
elaborate on Secure Channel characteristics in general and further describe RATS usage scenarios and
corresponding requirements for UCCS deployment.

# Characteristics of a Secure Channel {#secchan}

A Secure Channel for the conveyance of UCCS needs to provide the security
properties that would otherwise be provided by COSE for a CWT.
In this regard, UCCS is similar in security considerations to JWTs {{-jwtbcp}}
using the algorithm "none".  {{Section 3.2 of RFC8725@-jwtbcp}} states:

{:quote}
> \[...] if a JWT is cryptographically
protected end-to-end by a transport layer, such as TLS using
cryptographically current algorithms, there may be no need to apply another
layer of cryptographic protections to the JWT.  In such cases, the use of
the "none" algorithm can be perfectly acceptable.

The security considerations discussed, e.g., in {{Sections 2.1, 3.1,
and 3.2 of RFC8725@-jwtbcp}} apply in an analogous way to the use of UCCS as
elaborated on in this document.
In particular, the need to "Use Appropriate Algorithms" ({{Section 3.2
of RFC8725@-jwtbcp}}) includes choosing appropriate cryptographic
algorithms for setting up and protecting the Secure Channel.
For instance, their cryptographic strength should be at least as
strong as any cryptographic keys the Secure Channel will be used for
to protect in transport.
{{tab-algsec}} in {{algsec}} provides references to some more security
considerations for specific cryptography choices that are discussed in
the COSE initial algorithms specification {{-cose-new-algs}}.

Secure Channels are often set up in a handshake protocol that mutually
derives a session key, where the handshake protocol establishes the
(identity and thus) authenticity of one or both ends of the communication.
The session key can
then be used to provide confidentiality and integrity of the transfer of
information inside the Secure Channel.
(Where the handshake did not provide a mutually secure channel,
further authentication information can be conveyed by the party not
yet authenticated, leading to a mutually secured channel.)
A well-known example of a such a
Secure Channel setup protocol is the TLS {{-tls}} handshake; the
TLS record protocol can then be used for secure conveyance.

As UCCS were initially created for use in RATS Secure Channels, the following
section provides a discussion of
their use in these channels.  Where other environments are intended to be
used to convey UCCS, similar considerations need to be documented before
UCCS can be used.

# UCCS in RATS Conceptual Message Conveyance

This section describes a detailed usage scenario for UCCS in the
context of RATS in conjunction with its attendant security
requirements.
The use of UCCS tag CPA601 outside of the RATS context MUST come with additional instruction leaflets and security considerations.

For the purposes of this section, any RATS role can be the sender or the receiver of the UCCS.

Secure Channels can be transient in nature.  For the purposes of this
specification, the mechanisms used to establish a Secure Channel are out of
scope.

In the scope of RATS Claims, the receiver MUST
authenticate the sender as part of the establishment of the Secure Channel.
Furthermore, the channel MUST provide integrity of the communication between the
communicating RATS roles.
For data confidentiality {{-sec-glossary}}, the receiving side MUST be
authenticated as well; this is achieved if the sender and receiver
mutually authenticate when establishing the Secure Channel.
The quality of the receiver's authentication and authorization will
influence whether the sender can disclose the UCCS.

The extent to which a Secure Channel can provide assurances that UCCS
originate from a trustworthy Attesting Environment depends on the
characteristics of both the cryptographic mechanisms used to establish the
channel and the characteristics of the Attesting Environment itself.
The assurance provided to a Relying Party depends on the authenticity
and integrity properties of the Secure Channel used for conveying
the UCCS to it.

Ultimately, it is up to the receiver's policy to determine whether to accept
a UCCS from the sender and to determine the type of Secure Channel it must negotiate.
While the security considerations of the cryptographic algorithms used are similar
to COSE, the considerations of the Secure Channel should also adhere to the policy
configured at each of end of the Secure Channel.  However, the policy controls
and definitions are out of scope for this document.

Where an Attesting Environment serves as an endpoint of a Secure
Channel used to convey a UCCS, the security assurance required of that
Attesting Environment by a Relying Party generally calls for the
Attesting Environment to be implemented using techniques designed to
provide enhanced protection from an attacker wishing to tamper with or
forge UCCS originating from that Attesting Environment.
A possible approach might be to implement the Attesting Environment in
a hardened environment such as a TEE {{-teep}} or a TPM {{TPM2}}.

When UCCS emerge from the Secure Channel and into the receiver, the security
properties of the secure channel no longer protect the UCCS, which now are subject to the same security properties
as any other unprotected data in the Verifier environment.
If the receiver subsequently forwards UCCS, they are treated as though they originated within the receiver.

The Secure Channel context does not govern fully formed CWTs in the
same way it governs UCCS.
As with Entity Attestation Tokens (EATs, see {{-eat}}) nested in other EATs ({{Section 4.2.18.3 (Nested Tokens)
of -eat}}), the Secure
Channel does not endorse fully formed CWTs transferred through it.
Effectively, the COSE envelope of a CWT (or a nested EAT) shields the
CWT Claims Set from the endorsement of the secure channel.
(Note that EAT might add a nested UCCS
Claim, and this statement does not apply to UCCS nested into UCCS, only to
fully formed CWTs.)


# Considerations for Using UCCS in Other RATS Contexts

This section discusses two additional usage scenarios for UCCS in the
context of RATS.

## Delegated Attestation

Another usage scenario is that of a sub-Attester that has no signing
keys (for example, to keep the implementation complexity to a minimum)
and has a Secure Channel, such as local inter-process communication,
to interact with a lead Attester (see "Composite Device", {{Section 3.3
of -rats}}).
The sub-Attester produces a UCCS with the required CWT Claims Set and sends the UCCS through the Secure Channel to the lead Attester.
The lead Attester then computes a cryptographic hash of the UCCS and
protects that hash using its signing key for Evidence, for example,
using a Detached-Submodule-Digest or Detached EAT Bundle ({{Section 5 of -eat}}).

## Privacy Preservation

A Secure Channel which preserves the privacy of the Attester may provide
security properties equivalent to COSE, but only inside the life-span of the
session established.  In general, when a privacy preserving Secure
Channel is employed for conveying a conceptual message, the receiver
cannot correlate the message with the senders of
other received UCCS messages beyond the information the Secure Channel
authentication provides.

An Attester must consider whether any UCCS it returns over a privacy
preserving Secure Channel compromises the privacy in unacceptable ways.  As
an example, the use of the EAT UEID Claim ({{Section 4.2.1 of -eat}}) in UCCS over a privacy
preserving Secure Channel allows a Verifier to correlate UCCS from a single
Attesting Environment across many Secure Channel sessions. This may be
acceptable in some use-cases (e.g., if the Attesting Environment is a
physical sensor in a factory) and unacceptable in others (e.g., if the
Attesting Environment is a user device belonging to a child).

# IANA Considerations

## CBOR Tag registration

In the CBOR Tags registry {{-tags}} as defined in {{Section 9.2 of
RFC8949@-cbor}}, IANA is requested to allocate the tag in {{tab-tag-values}} from
the Specification Required space (1+2 size), with the present document
as the specification reference.

| Tag    | Data Item | Semantics                             |
| CPA601 | map (Claims-Set as per {{cddl}} of \[{{&SELF}}]) | Unprotected CWT Claims Set \[{{&SELF}}] |
{: #tab-tag-values cols='r l l' title="Values for Tags"}

[^cpa]

[^cpa]: RFC-Editor: This document uses the CPA (code point allocation)
      convention described in [I-D.bormann-cbor-draft-numbers].  For
      each usage of the term "CPA", please remove the prefix "CPA"
      from the indicated value and replace the residue with the value
      assigned by IANA; perform an analogous substitution for all other
      occurrences of the prefix "CPA" in the document.  Finally,
      please remove this note.

## Media-Type application/uccs+cbor Registration {#media-type}


IANA is requested to add the following Media-Type to the "Media Types"
registry {{IANA.media-types}}.

| Name      | Template              | Reference               |
| uccs+cbor | application/uccs+cbor | {{media-type}} of {{&SELF}} |
{: #new-media-type title="Media Type Registration"}


{:compact}
Type name:
: application

Subtype name:
: uccs+cbor

Required parameters:
: n/a

Optional parameters:
: n/a

Encoding considerations:
: binary (CBOR data item)

Security considerations:
: {{seccons}} of {{&SELF}}

Interoperability considerations:
: none

Published specification:
: {{&SELF}}

Applications that use this media type:
: Applications that transfer Unprotected CWT Claims Set(s) (UCCS) over
  Secure Channels

Fragment identifier considerations:
: The syntax and semantics of
      fragment identifiers is as specified for "application/cbor".  (At
      publication of this document, there is no fragment identification
      syntax defined for "application/cbor".)

Additional information:
: Deprecated alias names for this type:
  : N/A

  Magic number(s):
  : N/A

  File extension(s):
  : .uccs

  Macintosh file type code(s):
  : N/A

Person and email address to contact for further information:
: RATS WG mailing list (rats@ietf.org)

Intended usage:
: COMMON

Restrictions on usage:
: none

Author/Change controller:
: IETF



## Content-Format registration {#ct}

IANA is requested to register a Content-Format number in the "CoAP
Content-Formats" subregistry, within the "Constrained RESTful
Environments (CoRE) Parameters" registry {{IANA.core-parameters}}, as
follows:

| Content Type          | Content Coding | ID     | Reference       |
| application/uccs+cbor | -              | TBD601 | {{ct}} of {{&SELF}} |
{: #content-format-reg title="Content-Format Registration" }

[^tbd]

[^tbd]: RFC editor: please replace TBD601 by the number actually
    assigned by IANA (601 is suggested).

# Security Considerations {#seccons}

The security considerations of {{-cbor}} apply.
The security considerations of {{-cwt}} need to be applied analogously,
replacing the function of COSE with that of the Secure Channel; in
particular "it is not only important to protect the CWT in transit but also to ensure that the recipient can authenticate the party that assembled the claims and created the CWT".

{{secchan}} discusses security considerations for Secure Channels, in which
UCCS might be used.
This document provides the CBOR tag definition for UCCS and a discussion
on security consideration for the use of UCCS in RATS.  Uses of UCCS outside the scope of
RATS are not covered by this document.  The UCCS specification -- and the
use of the UCCS CBOR tag, correspondingly -- is not intended for use in a
scope where a scope-specific security consideration discussion has not
been conducted, vetted and approved for that use.
In order to be able to use the UCCS CBOR tag in another such scope,
the secure channel and/or the application protocol (e.g., TLS and the
protocol identified by ALPN) MUST specify the roles of the endpoints
in a fashion that the security properties of conveying UCCS via a
Secure Channel between the roles are well-defined.

## General Considerations

Implementations of Secure Channels are often separate from the application
logic that has security requirements on them.  Similar security
considerations to those described in {{-cose}} for obtaining the
required levels of assurance include:

* Implementations need to provide sufficient protection for private or
  secret key material used to establish or protect the Secure Channel.
* Using a key for more than one algorithm can leak information about the
  key and is not recommended.
* An algorithm used to establish or protect the Secure Channel may have
  limits on the number of times that a key can be used without leaking
  information about the key.
* Evidence in a UCCS conveyed in a Secure Channel generally cannot be
  used to support trust in the credentials that were used to establish
  that secure channel, as this would create a circular dependency.

The Verifier needs to ensure that the management of key material used to
establish or protect the Secure Channel is acceptable. This may include
factors such as:

* Ensuring that any permissions associated with key ownership are respected
  in the establishment of the Secure Channel.
* Using cryptographic algorithms appropriately.
* Using key material in accordance with any usage restrictions such as
  freshness or algorithm restrictions.
* Ensuring that appropriate protections are in place to address potential
  traffic analysis attacks.

## Algorithm-specific Security Considerations {#algsec}

{{tab-algsec}} provides references to some security considerations of
specific cryptography choices that are discussed in {{-cose-new-algs}}.

| Algorithm         | Reference                         |
|-------------------|-----------------------------------|
| AES-CBC-MAC       | {{Section 3.2.1 of -cose-new-algs}} |
| AES-GCM           | {{Section 4.1.1 of -cose-new-algs}} |
| AES-CCM           | {{Section 4.2.1 of -cose-new-algs}} |
| ChaCha20/Poly1305 | {{Section 4.3.1 of -cose-new-algs}} |
{: #tab-algsec title="Algorithm-specific Security Considerations"}


--- back

# CDDL

This appendix is informative.

The Concise Data Definition Language (CDDL), as defined in {{-cddl}} and
{{-control1}}, provides an easy and unambiguous way to express
structures for protocol messages and data formats that use CBOR or
JSON.

{{-cwt}} does not define CDDL for CWT Claims Sets.


[^cpa601]

[^cpa601]: RFC-Editor: This document uses the CPA (code point allocation)
      convention described in [I-D.bormann-cbor-draft-numbers].
      Please replace the number 601 in the code blocks below by the
      value that has been assigned for CPA601 and remove this note.

In {{fig-claims-set}},
this CDDL model shows how to use CDDL
for defining the CWT Claims Set defined in {{-cwt}}.
Note that these CDDL rules
have been built such that they also can describe {{-jwt}} Claims sets by
disabling feature "cbor" and enabling feature "json", but this
flexibility is not the subject of the present document.

~~~ cddl
UCCS-Untagged = Claims-Set
UCCS-Tagged = #6.601(UCCS-Untagged)

Claims-Set = {
 * $$Claims-Set-Claims
 * Claim-Label .feature "extended-claims-label" => any
}
Claim-Label = CBOR-ONLY<int> / text
string-or-uri = text

$$Claims-Set-Claims //= ( iss-claim-label => string-or-uri )
$$Claims-Set-Claims //= ( sub-claim-label => string-or-uri )
$$Claims-Set-Claims //= ( aud-claim-label => string-or-uri )
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

Specifications that define additional Claims should also supply
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

;;; Insert the required CDDL from RFC 9052 to complete these
;;; definitions.  This can be done manually or automated by a
;;; tool that implements an import directive such as:
;# import rfc9052
~~~
{: sourcecode-name="uccs-additional-examples.cddl"}

# Example

This appendix is informative.

The example CWT Claims Set from {{Appendix A.1 of -cwt}} can be turned into
a UCCS by enclosing it with a tag number CPA601:

~~~~ cbor-diag
 601(
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
<!--  LocalWords:  Verifier's CWTs Attester Verifier FCFS
 -->

# JSON Support

This appendix is informative.

The above definitions, concepts and security considerations all may be applied to define a JSON-encoded Claims-Set.
Such an unsigned Claims-Set can be referred to as a "UJCS", an "Unprotected JWT Claims Set".
The CDDL definition in {{fig-claims-set}} can be used for a "UJCS".

~~~ cddl
UJCS = Claims-Set
~~~

# EAT

This appendix is informative.

The following CDDL adds UCCS-format and UJCS-format tokens to EAT using its predefined extension points (see {{Section 4.2.18 (submods) of -eat}}).

~~~ cddl
$EAT-CBOR-Tagged-Token /= UCCS-Tagged
$EAT-CBOR-Untagged-Token /= UCCS-Untagged

$JSON-Selector /= [type: "UJCS", nested-token: UJCS]
~~~

--- back

Acknowledgements
================
{:unnumbered}

{{{Laurence Lundblade}}} suggested some improvements to the CDDL.
{{{Carl Wallace}}} provided a very useful review.
