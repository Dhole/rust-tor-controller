# Tor rust controller

This is a Work in Progress.

This should eventually be a rust library to control the tor deameon through the
control protocol [1].

The library should provide an interface similar to stem [2].

[1] https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
[2] https://stem.torproject.org

## DONE

- Do error handling: make all functions return Results, and change all the
  unwrap()'s to try!()'s.
- Randomize ClientNonce.
- Verify ServerHash.
- Implement TCP connection.
- Implement Unix socket connection.
- Implement AuthCookie authentication.
- Implement a utility to launch the tor daemon

## TODO

- Implement the different methods of authentication (Cookie, HashedPassword,
  Null).
- Unquote strings.
- Implement async events, probably by registering callbacks and keeping a thread
  running and reading incoming messages.
- Allow passing a configuration to the tor process.
- Add creation, deletion and listing of hidden services.
- ...
