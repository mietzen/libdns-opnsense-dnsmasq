DEVELOPER INSTRUCTIONS:
=======================

This repo is a template for developers to use when creating new [libdns](https://github.com/libdns/libdns) provider implementations.

Be sure to update:

- The package name
- The Go module name in go.mod
- The latest `libdns/libdns` version in go.mod
- All comments and documentation, including README below and godocs
- License (must be compatible with Apache/MIT)
- All "TODO:"s is in the code
- All methods that currently do nothing

**Please be sure to conform to the semantics described at the [libdns godoc](https://github.com/libdns/libdns).**

_Remove this section from the readme before publishing._

---

OPNsense dnsmasq for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/mietzen/libdns-opnsense-dnsmasq)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for OPNsense dnsmasq, allowing you to manage DNS records.

It allows you to set local host overrides via Caddy. This module **CAN'T** be used for `acme`!
