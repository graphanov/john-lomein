"""Credential-isolated release broker package.

The package initializer deliberately imports nothing.  Instance runtimes
receive only this initializer plus the credential-free protocol and receipt
verification modules; importing either client module must therefore never
pull in the privileged GitHub App or live-service implementation.

Privileged broker code imports its concrete modules explicitly.  Keeping that
boundary explicit also prevents an innocent ``import release_broker`` in a
client runtime from failing merely because privileged modules are absent.
"""
