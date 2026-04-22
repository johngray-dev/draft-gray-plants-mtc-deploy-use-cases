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

informative:

...

--- abstract

The Merkle Tree Certificate (MTC) structure as defined in
draft-ietf-plants-merkle-tree-certs defines a new form of X.509 certificate
that integrates logging with certificate issues.  It was mainly designed to
help mitigate the cost of signatures sizes in the Post Quantum context. This
is achieved by replacing the traditional signature with a Merkle Tree
Signature containing the authentication path to a set of landmarks in
the Merkle Tree structure which are available to the signature verifier. Cost
savings are magnified in cases like the Web PKI where there may be multiple
Signer Certifcate Timestamps (SCT).  For environments where SCTs might not be
used, the cost benefit may be less pronounced. The purpose of the
specification is to explore these types of use-cases which may help optimizate
general purpose PKI usages, particularily in the Post Quantum context where
signatures sizes and performances characteristics may hinder operations.


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
