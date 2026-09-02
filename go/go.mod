// The tooling, as one static binary. See ../GO-REWRITE.md for why: so that
// somebody who is not us can reproduce a finding.
//
// No third-party dependencies, deliberately. A binary handed to a vendor so
// they can confirm a defect should not need a module proxy to build, and the
// only thing here that would want a library -- one scalar field out of
// project.yaml -- is cheaper to scan for than to depend on.
module pgfuzz

go 1.27
