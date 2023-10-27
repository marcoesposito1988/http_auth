## 1.0.4

- Fixed quoting of some HTTP headers (thanks to @aedalzotto)
 
## 1.0.3

- Added `close()` method to `NegotiateAuthClient` (thanks to @KrohnMi)
 
## 1.0.2

- Updated http dependency
- More code linting
 
## 1.0.1

- Code linting

## 1.0.0

- Migrated to sound null safety

## 0.3.2

- Updated dependencies for compatibility with Flutter2

## 0.3.1

- Made NegotiateAuthClient robust to repeated WWW-Authenticate headers in the server response (thanks to @jbash for 
the issue report)

## 0.3.0

- Added NegotiateAuthClient that automatically detects the authentication method (thanks to @hpoul)
- General linting (thanks to @hpoul)
- Reorganized the tests for consistency 

## 0.2.9

- Code linting 

## 0.2.8

- Call to inner `Client`'s `close()` was missing (thanks to @SiLeader) 

## 0.2.7

- Added reauthentication after 401 (thanks to @kendfinger)

## 0.2.6

- Added fix for URLs with a query (thanks to thuette for the implementation and Pacane for reporting the fix)

## 0.2.5

- Updated syntax

## 0.2.4

- Fixed parsing of Auth header (thanks to @graknol)

## 0.2.3

- Fixed warnings

## 0.2.2

- Updated http dependency requirement

## 0.2.1

- Removed dependency from cryptoutils

## 0.2.0

- Upgraded for Dart 2.0 stable

## 0.1.3

- Upgraded dependencies

## 0.1.2

- Fixed handling of requests with a body.

## 0.1.1

- Fixed nonce counter.

## 0.1.0

- Initial version.
