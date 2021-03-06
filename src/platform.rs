
#[cfg(unix)]
mod unix {
    use control::Controller;
    use control::Connection;

    use std::path::Path;
    use std::io;
    use std::io::BufReader;
    use std::io::BufWriter;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    impl Controller<UnixStream> {
        pub fn from_socket_file<P: AsRef<Path>>(path: P) -> Result<Controller<UnixStream>, io::Error> {
            Ok(Controller { con: Connection::<UnixStream>::connect(path)? })
        }

        pub fn close(&mut self) -> Result<(), io::Error> {
            self.con.close()
        }
    }

    impl Connection<UnixStream> {
        fn connect<P: AsRef<Path>>(path: P) -> Result<Connection<UnixStream>, io::Error> {
            let raw_stream = UnixStream::connect(path)?;
            let buf_reader = BufReader::new(raw_stream.try_clone()?);
            let buf_writer = BufWriter::new(raw_stream.try_clone()?);
            Ok(Connection { raw_stream, buf_reader, buf_writer })
        }

        fn close(&mut self) -> Result<(), io::Error> {
            self.raw_stream.shutdown(Shutdown::Both)
        }
    }

}
