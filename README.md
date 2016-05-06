# Tor rust controller

This is a Work in Progress.

This should eventually be a rust library to control the tor deameon through the
control protocol [1].

The library should provide an interface similar to stem [2].

[1] https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
[2] https://stem.torproject.org

## TODO

- Do error handling: make all functions return Results, and change all the
  unwrap()'s to try!()'s.
- Implement the different methods of authentication.
- Unquote strings.
- Randomize ClientNonce
- Verify ServerHash
- ...
