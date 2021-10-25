use std::io::{Error, ErrorKind, Read, Result};
use std::iter::Iterator;

#[derive(Debug)]
pub struct Chunk<I>
where
    I: Iterator<Item = Vec<u8>>,
{
    finished: bool,
    buffer: Vec<u8>,
    producer: I,
}

impl<I> Chunk<I>
where
    I: Iterator<Item = Vec<u8>>,
{
    pub fn new(producer: I) -> Self {
        Self {
            finished: false,
            buffer: Vec::with_capacity(1024 * 1024),
            producer,
        }
    }
}

impl<I> Read for Chunk<I>
where
    I: Iterator<Item = Vec<u8>>,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "input buf empty"));
        }

        if self.finished {
            return Ok(0);
        }

        let len1 = buf.len();
        while self.buffer.len() < len1 {
            match self.producer.next() {
                Some(bytes) => {
                    self.buffer.extend(bytes);
                }
                None => break,
            }
        }
        let len2 = std::cmp::min(len1, self.buffer.len());
        let vec1: Vec<u8> = self.buffer.drain(0..len2).collect();
        for (n, &x) in vec1.iter().enumerate() {
            buf[n] = x;
        }

        self.finished = self.buffer.is_empty();
        log::trace!(
            "buffer len {}, finished {}",
            self.buffer.len(),
            self.finished
        );

        Ok(len2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_read() {
        let mut buf = [0u8; 5];
        let list1 = (65..71).collect::<Vec<u8>>();
        let list2 = (71..91).collect::<Vec<u8>>();
        let list3 = (97..122).collect::<Vec<u8>>();
        let producer1: Vec<Vec<u8>> = vec![list1, list2, list3];
        let producer2 = producer1.clone();

        let mut chunk = Chunk::new(producer1.into_iter());
        while let Ok(len) = chunk.read(&mut buf) {
            println!("{} bytes, {:?}", len, buf);
            buf.fill(0);
        }

        let mut buf2 = vec![];
        let mut chunk1 = Chunk::new(producer2.into_iter());
        let result = chunk1.read(&mut buf2);
        assert_eq!(result.is_err(), true);
        let er = result.unwrap_err();
        assert_eq!(er.kind(), ErrorKind::InvalidInput);
    }
}
/*
pub mod adapter {
    use std::io::Read;

    pub struct Reader<T: Read> {
        pub buf_size: usize,
        pub reader: T,
    }

    impl<T: Read> Iterator for Reader<T> {
        type Item = Vec<u8>;

        fn next(&mut self) -> Option<Self::Item> {
            let mut buf = vec![0; self.buf_size];

            match self.reader.read(&mut buf) {
                Ok(len) => Some(buf.drain(0..len).collect()),
                Err(_) => None,
            }
        }
    }
}
*/
