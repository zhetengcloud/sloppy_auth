use crate::{
    aws::auth::Sign,
    util::{self, Headers},
};
use std::io::Read;

pub struct Holder<'a, T: Read, H: Headers> {
    pub buf_size: usize,
    pub reader: T,
    prev_signature: Option<String>,
    signer: Sign<'a, H>,
    state: State,
}

impl<'a, R: Read, H: Headers> Holder<'a, R, H> {
    pub fn new(buf_size: usize, reader: R, signer: Sign<'a, H>) -> Self {
        Self {
            buf_size,
            reader,
            prev_signature: None,
            signer,
            state: State::Body,
        }
    }
}

enum State {
    Body,
    Final,
    Finished,
}

impl<'a, R: Read, H: Headers> Iterator for Holder<'a, R, H> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            State::Finished => None,
            State::Body => {
                let prev = match &self.prev_signature {
                    Some(s) => s.clone(),
                    None => self.signer.calc_seed_signature(),
                };

                let mut data = Vec::<u8>::with_capacity(self.buf_size);
                let mut buf = [0u8; 128 * 1204];
                loop {
                    match self.reader.read(&mut buf) {
                        Ok(len) => {
                            if len < 1 {
                                self.state = State::Final;
                                break;
                            } else {
                                data.extend_from_slice(&buf[0..len]);
                                if data.len() > self.buf_size {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            self.state = State::Final;
                            break;
                        }
                    }
                }

                let new_sign = self.signer.chunk_sign(prev, data.clone());
                self.prev_signature = Some(new_sign.clone());
                let chunk = util::concat_chunk(data, new_sign);
                Some(chunk)
            }
            State::Final => {
                self.state = State::Finished;
                if let Some(prev) = &self.prev_signature {
                    let data = vec![];
                    let new_sign = self.signer.chunk_sign(prev.clone(), data.clone());
                    self.prev_signature = Some(new_sign.clone());
                    let chunk = util::concat_chunk(data, new_sign);
                    Some(chunk)
                } else {
                    None
                }
            }
        }
    }
}
