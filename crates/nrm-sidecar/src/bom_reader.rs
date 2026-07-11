use std::io::{self, Read};

const UTF8_BOM: [u8; 3] = [0xef, 0xbb, 0xbf];

/// Removes one transport-injected UTF-8 BOM before an otherwise binary stream.
///
/// Windows OpenSSH installations whose default shell is Windows PowerShell can
/// prefix a nested native process's stdout with a BOM. Agent frames and LSP
/// headers are binary protocols and cannot contain that shell artifact.
pub(crate) struct LeadingBomReader<R> {
    inner: R,
    prefix: [u8; UTF8_BOM.len()],
    prefix_len: usize,
    prefix_offset: usize,
    initialized: bool,
    pending_error: Option<io::Error>,
}

impl<R> LeadingBomReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            prefix: [0; UTF8_BOM.len()],
            prefix_len: 0,
            prefix_offset: 0,
            initialized: false,
            pending_error: None,
        }
    }
}

impl<R: Read> LeadingBomReader<R> {
    fn initialize(&mut self) -> io::Result<()> {
        if self.initialized {
            return Ok(());
        }

        let mut read = 0;
        while read < UTF8_BOM.len() {
            match self.inner.read(&mut self.prefix[read..]) {
                Ok(0) => break,
                Ok(count) => read += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if read != 0 => {
                    // `Read` callers must observe bytes already obtained before
                    // a later read failure. Leave the underlying error for the
                    // next call instead of discarding this partial prefix.
                    self.prefix_len = read;
                    self.initialized = true;
                    self.pending_error = Some(error);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        self.prefix_len = if read == UTF8_BOM.len() && self.prefix == UTF8_BOM {
            0
        } else {
            read
        };
        self.initialized = true;
        Ok(())
    }
}

impl<R: Read> Read for LeadingBomReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        self.initialize()?;

        let mut written = 0;
        if self.prefix_offset < self.prefix_len {
            let available = &self.prefix[self.prefix_offset..self.prefix_len];
            let count = available.len().min(output.len());
            output[..count].copy_from_slice(&available[..count]);
            self.prefix_offset += count;
            written += count;
        }
        if written == output.len() {
            return Ok(written);
        }

        if self.pending_error.is_some() {
            return if written == 0 {
                Err(self
                    .pending_error
                    .take()
                    .expect("pending error was present"))
            } else {
                Ok(written)
            };
        }

        match self.inner.read(&mut output[written..]) {
            Ok(count) => Ok(written + count),
            Err(error) if written != 0 => {
                self.pending_error = Some(error);
                Ok(written)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _};

    use super::LeadingBomReader;

    struct OneByteReader<R>(R);

    impl<R: std::io::Read> std::io::Read for OneByteReader<R> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let len = output.len().min(1);
            self.0.read(&mut output[..len])
        }
    }

    fn read_all(input: impl std::io::Read) -> Vec<u8> {
        let mut output = Vec::new();
        LeadingBomReader::new(input)
            .read_to_end(&mut output)
            .unwrap();
        output
    }

    #[test]
    fn strips_one_bom_even_when_the_prefix_arrives_one_byte_at_a_time() {
        let input = OneByteReader(Cursor::new(b"\xef\xbb\xbfContent-Length: 2\r\n"));
        assert_eq!(read_all(input), b"Content-Length: 2\r\n");
    }

    #[test]
    fn preserves_non_bom_and_short_binary_prefixes_exactly() {
        assert_eq!(
            read_all(Cursor::new(b"\0\0\0\x05hello")),
            b"\0\0\0\x05hello"
        );
        assert_eq!(read_all(Cursor::new(b"\xef\xbb")), b"\xef\xbb");
        assert_eq!(
            read_all(Cursor::new(b"\xef\xbb\xbf\xef\xbb\xbfbody")),
            b"\xef\xbb\xbfbody"
        );
        assert!(read_all(Cursor::new(Vec::<u8>::new())).is_empty());
    }

    struct ErrorAfterPrefix {
        state: u8,
    }

    impl std::io::Read for ErrorAfterPrefix {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.state == 0 {
                self.state = 1;
                let prefix = [0xef, 0xbb];
                let count = prefix.len().min(output.len());
                output[..count].copy_from_slice(&prefix[..count]);
                return Ok(count);
            }
            if self.state == 1 {
                self.state = 2;
                return Err(std::io::Error::other("one-shot trailing failure"));
            }
            Ok(0)
        }
    }

    #[test]
    fn returns_a_partial_prefix_before_propagating_a_later_read_error() {
        let mut reader = LeadingBomReader::new(ErrorAfterPrefix { state: 0 });
        let mut output = [0; 8];
        assert_eq!(reader.read(&mut output).unwrap(), 2);
        assert_eq!(&output[..2], b"\xef\xbb");
        assert_eq!(
            reader.read(&mut output).unwrap_err().kind(),
            std::io::ErrorKind::Other
        );
        assert_eq!(reader.read(&mut output).unwrap(), 0);
    }
}
