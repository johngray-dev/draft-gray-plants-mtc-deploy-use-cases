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
 - Merke Tree Certificate
 - Post Quantum
 - PKI
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
 -
    ins: L. Tindell
    name: Luke Tindell
    org: UK National Cyber Security Centre
    email: luke.t2@ncsc.gov.uk
    country: United Kingdom


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

Merkle Tree Certificates (MTC) have been designed to solve two problems for the WebPKI:

1. **Size.** A *landmark-relative Merkle Tree Certificate* is small as it
  only contains a public key and a small Merkle Tree inclusion proof.
2. **Downgrade Detection.** MTC ensures Certificate Transparency is post-quantum secure, and with that
   allows detection of post-quantum downgrade attacks.

Besides solving these two problems, MTC has additional benefits.

**Batch Signing.** MTC reduces the load on the CA because a single signature is used for a batch of certificates.

A PKI that operates with any of these three challenges could benefit from MTC.
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

The use of a Merkle tree allows for batch signing, and the cost of a signature is
amortized over the number of certificates at the leaf notes.

If a verifier has out-of-band knowledge of the treehead used (which in
that case is called a *landmark*), then it can be satisfied with
the landmark-relative certificate that leaves out the signatures.

## Batch size trade-offs

A PKI can make trade-offs when selecting MTC batch sizes for both
checkpoints and landmarks.

For checkpoints the trade-off is between computational cost of signatures and
the size of standalone certificates. Smaller checkpoint batches require more
frequent signatures, but reduce the size of the inclusion proofs for standalone
certificates. Conversely, larger batches reduce the signature frequency but
increase the size of inclusion proofs for standalone certificates.

For landmarks the trade-offs are between relying party storage costs and the
size of landmark-relative certificates. Fewer landmarks require less storage on
the relying party, but result in each landmark representing a larger Merkle
tree, which increases the size of the inclusion proof for the landmark-relative
certificate. Conversely, more frequent landmarks would give smaller proofs for
the landmark-relative certificate but require more storage on the relying party.

Both batch sizes will be influenced by the specifics of the PKI, including the
frequency of certificate signing requests and acceptable issuance latency.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Use cases

## Verification of LandMark-Relative Merkle Tree Certificates outside the WebPKI

Merkle Tree Certificates which only contain the inclusion proof
to a signed tree head can only be verified when the verifier contains the
landmark that completes the inclusion proof contained in the Certificate
signature field.  If the certificate is in a non webPKI environment where it has an
online connection it should be possible for the verifier to request a refresh
of its landmarks.  There are different ways this can be accomplished:

1. It can be done dynamically, on demand by the verifier.  A mechanism
   that fetches landmarks from a distribution location could be added to
   the certificate which could be used to complete this lookup.  Such a
   mechanism could be similar to an X.509 CRLDP, except in this case it
   could be a "Landmark Distribution Point".

2. The landmarks could be fetched periodically by the verifier (or a
   distribution system could push them down to the verifiers).

3. They could be fetched by a locally defined policy.  For example they
   could be pre-shared at a location governed by a local policy.


### Landmark Distribution Point Fetching Mechanism

   The ldpBaseURIs X509 V3 extension is held by the Issuer of the Signatureless
   Merkle Tree Certificate and contains the SEQUENCE of LandmarkDistributionPoints, each
   which is a LandmarkDistributionPoint of IA5String.  Each refers to a BaseURI location
   indicating where the landmarks are published.

~~~
id-pe-ldpBaseURIs OBJECT IDENTIFIER ::=  { id-pe TBD }

LandmarkDistributionPoints ::= SEQUENCE (1..MAX) OF LandmarkDistributionPoint

LandmarkDistributionPoint ::= IA5String
~~~


   The Inclusion Proof structure defined in I-D.ietf-plants-merkle-tree-certs
   uses the following structure:

~~~
struct {
    uint64 start;
    uint64 end;
    HashValue inclusion_proof<0..2^16-1>;
    MTCSignature signatures<0..2^16-1>;
} MTCProof;
~~~

   Note that it contains start and end values which indicate
   the corresponding parameters of the chosen subtree.  To request the
   required landmark, the client simply combines the URL as follows:

   LandmarkDistributionPoint?st=start?ed=end

   This allows the verifier to request the required landmark so the
   inclusion proof can be verified.

   The verifier needs to trust the issuer as per RFC 5280.


### Format of Landmark

The format of the landmark is defined in section 6.3.3
of I-D.ietf-plants-merkle-tree-certs

As mentioned above, the verifier may need to request the landmark if it
is not readily available.

This draft proposes an extension to the landmark format specified in section
6.3.3 of I-D.ietf-plants-merkle-tree-certs which defines a mechanism for
publishing active landmarks.

The current landmark format describes the tree sizes associated for each
landmark.  However, it does not provide a mechanism for establishing a
cryptographic relationship between a previously published landmark and a
more recent landmark.  This document defines this mechanism as a Landmark
subtree consistency Proof.  It includes carrying the necessary hashes so
that there is a subtree consistency proof from one landmark to the next. 
The calculation of the subtree consistency proof from one landmark to the
next can occur when a new landmark is published.  See section
4.4 of I-D.ietf-plants-merkle-tree-certs for information on subtree
consistency proofs.  

This will allow for periodic and incremental updates for clients that need to
request information from the LDP server.

#### Landmark subtree consistency proof

A verifier requesting updated landmarks may require a lot of new landmarks.
Requiring the verifier to retrieve and validate every intermediate
landmark would increase both network traffic and signature
verification costs.

To address this problem, this document defines a 
LandmarkSubtreeProof object.  A LandmarkSubtreeProof provides cryptographic
evidence that a source landmark identified by one tree size is incorporated
into a target landmark identified by a larger tree size.

The LandmarkSubtreeProof does not modify the landmark publication
format defined in Section 6.3.3.  Instead, it is published as a
separate resource by the Landmark Distribution Point Server
(LDP Server).

The LandmarkSubtreeProof structure is defined as follows:

~~~
struct {
    uint64 source_tree_size;
    uint64 target_tree_size;

    HashValue consistency_proof<0..2^16-1>;
} LandmarkSubtreeProof;
~~~

Where:

source_tree_size (similar to start in MTCProof):
   The tree size corresponding to the source landmark.

target_tree_size (similar to end in MTCProof):
   The tree size corresponding to the target landmark.

consistency_proof:
   A proof demonstrating that the source landmark tree is a
   subtree of the target landmark tree.

The consistency_proof SHALL be constructed so that successful
verification demonstrates that all entries represented by the
source landmark are included in the target landmark and retain
their original ordering and contents.

A LandmarkProof MAY be generated when a new landmark is
published and MAY be retained by the Landmark Distribution
Point for subsequent retrieval by the verifier as needed.

### Landmark Subtree Proof Retrieval

A verifier validating an MTCProof obtains the corresponding
subtree information from the certificate and retrieves the
associated landmark file as described in Section 6.3.3.

If the verifier possesses a trusted landmark whose tree size is
greater than the retrieved landmark's tree size, the verifier
MAY obtain a set of LandmarkSubtreeProofSet connecting the two
landmarks.

#### Landmark Subtree Proof Set

A LandmarkSubtreeProofSet contains an ordered sequence of LandmarkSubtreeProof values. The first proof SHALL be verified against a trusted landmark root. Each subsequent proof SHALL be verified against the landmark root reconstructed from the preceding proof. Successful verification of all contained proofs establishes a cryptographic path from the trusted landmark to the target landmark.

~~~
struct {
    LandmarkSubtreeProof proofSet<0..2^16-1>;
} LandmarkSubtreeProofSet;
~~~

One possible retrieval mechanism is:

~~~
LandmarkDistributionPoint?
    source=<source_tree_size>&
    target=<target_tree_size>
~~~

TODO:  Agree on the URI format

The Landmark Distribution Point Server SHALL return a 
LandmarkSubtreeProofSet capable of demonstrating that the source landmark is
incorporated into the target landmark.

### Validation Procedure

A verifier SHALL perform the following steps:

1.  Extract the `start` and `end` values from the MTCProof.

2.  Retrieve the landmark file corresponding to the authenticated
    subtree by contacting the LDP server (or retrieving it
    from a local cache).

3.  Obtain a trusted target landmark if one is not already
    cached. For example, a likely candidate would be the latest
    landmark referenced by the Landmark File.

4.  Verify the signature(s) associated with the trusted target
    landmark.  If signature verification fails, the verifier MUST
    reject the certificate.

6.  If the source subtree landmark and trusted target landmark differ,
    retrieve a LandmarkSubtreeProofSet that establishes a
    sequence of authenticated subtree transitions between the
    source landmark and the trusted target landmark.

7.  Verify each LandmarkSubtreeProof contained in the
    LandmarkSubtreeProofSet in the order in which it appears.
    The first proof SHALL be verified against the source
    landmark. Each subsequent proof SHALL be verified against
    the landmark root reconstructed from the preceding proof.

8.  Successful verification of the complete
    LandmarkSubtreeProofSet SHALL establish that the source
    landmark tree is a cryptographic prefix of the trusted
    target landmark tree.

9.  Use the validated source landmark to verify the Inclusion
    Proof contained within the MTCProof.

10.  Accept the certificate if all verification steps succeed.

Successful completion of this procedure establishes that the
certificate entry is included in the authenticated subtree
identified by the source landmark and that the source landmark
is cryptographically bound via the verified LandmarkSubtreeProofSet
to the trusted target landmark.

### Efficiency Considerations

The purpose of LandmarkSubtreeProofs is to reduce the number of
landmarks and signatures that must be processed by a verifier.

Without LandmarkSubtreeProofs, a verifier may be required to retrieve
multiple intermediate landmarks and validate the signatures
associated with each landmark before reaching a currently
trusted landmark.

With LandmarkProofs, a verifier requires only:

* the source landmark;

* the trusted target landmark; and

* a LandmarkSubtreeProofSet connecting the corresponding tree sizes.

As a result, the number of signature verification operations is
independent of the number of intermediate landmarks published
between the source and target landmarks.

This property is particularly beneficial when signatures are
generated using computationally expensive algorithms,
including post-quantum signature algorithms.

### Skip links for efficiency

TODO:  Generating the consistency proof at the LDP server introduces an O(N^2) problem.  For efficiency, we likely want to cache landmark proofs as they are generated between each landmark.  For example 1->2, 2->3, 3->4 but also 1->3, 1-4, 2-4.  Thus O(n^2).  A better approach is to use a skip link which only generates O(Log(num_landmarks)) for each landmark.  For example, a system that issued a landmark every hour for 10 years would have 87,600 landmarks.  When landmark 87,601 is created, only 17 landmark proofs will need to be created.  It would also reduce the LandmarkSubtreeProofSet from O(num_landmarks) to O(Log(num_landmarks), greatly reducing bandwidth requirements!

### More items to be discussed:
- When a CA issues an MTC certificate, it will decide where the landmark will be published.  It needs to provide the LDP service.
- Current format uses start and end values from the inclusion proof.  This is nice because no other extension is needed in the EE certs
- Landmarks should be available in a predictable way.  The above format should meet this requirement.
- Do Landmark's contain a signature, or is it just the MTH and we use the cumulative landmarks along with the inclusion proof?
   - A:  No, there is one trusted target that contains a signature.  That trusted target should be cached so that the full PQ signatures doesn't need to be continually downloaded.  This is where MTC gets its efficiency.
- Is there a repository of test landmark certificates that we can use to test this mechanism?
   - A:  Seems like a good hackathon project!


### Landmark Distribution server
As mentioned above, the landmarks can be fetched dynamically as needed by
combining the start and end values from the MTCProof.  The LDP server fulfilling
these requests will need to parse the start and end values, aggregate the
require landmark subtrees together, and send the responce back to the client.
The responce format will be:

TODO:  DEFINE responce format


## Batching for performance optimization

**When**
Signatures are expensive computational operations.  Systems where
high signature throughput is important are good candidates for the use
of batch signing, as it can provide a sizeable performance optimization
(for example, device certificates).  Merkle Trees with leaves of size N
can be computed as hashes of the toBeSigned data, with a single signature
over the root of that Merkle Tree.  For example, a Merkle tree of size
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



## Just using transparency
TODO - discuss advantages of transparency logs
- Track mis-issued certificates in your private key
- CA's already have an audit trail - is there an advantage to using transparency logs
- Need a source of truth for cross checking


# Security Considerations

TODO Security


# IANA Considerations

This document requests a new id-pe-ldpBaseURIs extension for use with X.509 certificates
in the "SMI Security for PKIX Certificate Extension" registry (1.3.6.1.5.5.7.1).

--- back

# Acknowledgments
Thanks to David Benjamin and Bas Westerbaan for his help and review of this specification.
