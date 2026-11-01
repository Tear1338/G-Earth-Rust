use crate::packet::{error, Result};

/// Independent RC4 implementation for legacy protocol interoperability.
/// This is not a cipher for new applications.
#[derive(Clone)]
pub struct Rc4 {
    state: [u8; 256],
    x: u8,
    y: u8,
}
impl Rc4 {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(error("empty RC4 key"));
        }
        let mut state = [0u8; 256];
        for (i, b) in state.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Ok(Self { state, x: 0, y: 0 })
    }
    pub fn from_state(state: [u8; 256], x: u8, y: u8) -> Result<Self> {
        let mut seen = [false; 256];
        for b in state {
            if seen[b as usize] {
                return Err(error("RC4 state must be a permutation"));
            }
            seen[b as usize] = true;
        }
        Ok(Self { state, x, y })
    }
    pub fn state(&self) -> ([u8; 256], u8, u8) {
        (self.state, self.x, self.y)
    }
    pub fn apply(&mut self, bytes: &mut [u8]) {
        for b in bytes {
            self.x = self.x.wrapping_add(1);
            self.y = self.y.wrapping_add(self.state[self.x as usize]);
            self.state.swap(self.x as usize, self.y as usize);
            *b ^= self.state
                [self.state[self.x as usize].wrapping_add(self.state[self.y as usize]) as usize];
        }
    }
    pub fn rewind(&mut self, count: usize) {
        for _ in 0..count {
            self.state.swap(self.x as usize, self.y as usize);
            self.y = self.y.wrapping_sub(self.state[self.x as usize]);
            self.x = self.x.wrapping_sub(1);
        }
    }
}
