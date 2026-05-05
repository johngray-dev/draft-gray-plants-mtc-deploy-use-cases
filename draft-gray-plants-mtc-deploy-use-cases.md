---
title: "Merkle Tree Certificates Deployment Use Cases"
abbrev: "MTC Use Cases"
category: info

docname: draft-gray-plants-mtc-deploy-use-cases-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PKI, Logs, And Tree Signatures"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "PKI, Logs, And Tree Signatures"
  type: "Working Group"
  mail: "plants@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/plants"
  github: "johngray-dev/draft-gray-plants-mtc-deploy-use-cases"
  latest: "https://johngray-dev.github.io/draft-gray-plants-mtc-deploy-use-cases/draft-gray-plants-mtc-deploy-use-cases.html"

author:
 -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
 -
    ins: "D. Benjamin"
    name: "David Benjamin"
    organization: "Google LLC"
    email: davidben@google.com
 -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Cryptic Forest Software
    abbrev: Cryptic Forest
    city: Sioux Lookout, Ontario
    country: Canada
    email: mike@ounsworth.ca
 -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany


normative:
I-D.draft-ietf-plants-merkle-tree-certs-03:

informative:

...

--- abstract

Merkle Tree Certificates (MTC)
I-D.ietf-plants-merkle-tree-certs has been defined for the
use case of the WebPKI.
In this document we explore when and how MTC in parts or full can be used in different
use cases. Some of this use-cases may provide benefit for private PKI usage.


--- middle

# Introduction

EdNote: Before getting into the nitty gritty, let's start with the potential benefit

MTC has been designed to solve two problems for the WebPKI:

1. **Size.** A *landmark-relative Merkle Tree Certificate* is small as it
  only contains a public key and a small Merkle Tree authentication path.
2. **DD.** MTC ensures Certificate Transparency is post-quantum secure, and with that
   allows detection of post-quantum downgrade attacks after the fact.

Besides solving these two problems, MTC has additional benefits.

3. **Batch.** MTC reduces the load on the CA HSM by signing batches.

A PKI that faces any of these three challenges could benefit from MTC.
These advantages come with trade-offs:

1. The small *landmark-relative* MTCs can only be used if the verifier
   has been updated with recent *landmarks*. If the verifier is stale, it
   has to fall back to a larger *standalone* MTC or it will need a
   mechanism to be able to fetch the latest landmarks (refresh its
   state). The prover and verifier need a mechanism to negotiate whether
   to use the landmark-relative or standalone certificate.
2. For downgrade detection, the issuer needs to publish a log of issued
   certificates.
3. Batch sizing parameters will need to be carefully chosen to optimize
   system efficiency based on the particular use-case.

## Brief overview of MTC

A Merkle Tree Certificate is a regular X509 certificate with two
differences:

1. Instead of a single signature, an MTC can contain zero or more signatures:
   zero in the case of landmark-relative and one-or-more in case of standalone.
   One is by the issuer, and others are added when certificate transparency is required.
2. The contents of the certificate is not signed directly, but instead
   a Merkle tree head is signed, together with providing a proof-of-inclusion
   of the certificate contents in that Merkle tree.
 
The use of a Merkle tree allows for the batch signing.

If a verifier has out-of-band knowledge of the treehead used (which in
that case is called a *landmark*), then it can be satisfied with
the landmark-relative certificate that leaves out the signatures.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use cases

## Verification of signatureless Merkle Tree Certificates
Merkle Tree Certificates which only contain the inclusion proof
to a signed tree head can only be verified when it contains the landmark
that completes the include proof contained in the Certificate.  If
the certificate is in an environment where it has an online connection
it should be possible for the verifier to request a refresh of its
landmarks.   There are different ways this could be accomplished:

1. It could be done dynamically, on demand by the verifier.  A mechanism
   that fetches landmarks from a distribution location could be added to
   the certificate which could be used to complete this lookup.  Such a
   mechanism could be similar to an X.509 CRLDP, except in this case it
   could be a "Landmark Distribution Point".

   TODO:   Define the mechanism

   Potential Mechanism at Issuer:
   LandmarkDistributionPoints ::= SEQUENCE OF IA5String

   Current Signature proof field uses this:
   What is in signature field today:

struct {
    uint64 start;
    uint64 end;
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature signatures<0..2^16-1>;
} MTCProof;

   The client simply combined the URL as follows:
   
   LandmarkDistributionPoint?st=start?ed=end

   
   Verifier needs to trust the issuer.  Mechanism for landmark location
   should be in the issuer certificate.  For its subjects, they only need
   the start and end landmark location.
   

3. The landmarks could be fetched periodically by the verifier (or a
   verification system could push them down to the verifiers).

4. They could be fetched by a locally defined policy.  For example they
   could be pre-shared at a location governed by a local policy.

## Just using batching

**When**
Signatures are expensive computational operations.  Systems where
high signature throughput is important (for example, device certificates)
are good candidates for the use of batch signing, as it can provide a
sizeable performance optimization.  Merkle Trees with leaves of size N
can be computed as hashes of the toBeSigned data, with a single signature
over the root of that Merke Tree.  For example, a Merkle tree of size
2^12 would have 2^11 leaves and could represent 2048 signatures.  The
verifier would only need to create a single signature for each batch
of 2048 toBeSigned data values.  Larger sizes could be used to meet the
operational requirements of the system.

**Requirements**
The verifier could use the mechanism defined in "Verification of
signatureless Merkle Tree Certificates" above to verifiy the signature
when certificates are used.

TODO:  If a certificate is not used, the same kind of fetching mechanism
would be needed for the verifier but that would need to be provided by
some out-of-band mechanism.

Changing verification code; only one signature.

## Just using landmarks

**When** ...
**Requirements** ...

## Just using transparency
- Track mis-issued certificates in your private key
- CA's already have an audit trail - is there an advantage to using transparency logs
- Need a source of truth for cross checking

# Different ways of acquiring landmarks


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
Thanks to Bas Westerban for his help and review of this specification.
{:numbered="false"}

TODO acknowledge.
