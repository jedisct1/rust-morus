#![cfg_attr(not(feature = "std"), no_std)]

use core::convert::TryInto;
use core::fmt;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidTag,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Morus-1280-128 authentication tag
pub type Tag = [u8; 16];

/// Morus-1280-128 key
pub type Key = [u8; 16];

/// Morus-1280-128 nonce
pub type Nonce = [u8; 16];

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct State {
    s: [[u64; 4]; 5],
}

impl State {
    fn update(&mut self, input: &[u64; 4]) {
        let s = &mut self.s;
        s[0][0] ^= s[3][0];
        s[0][1] ^= s[3][1];
        s[0][2] ^= s[3][2];
        s[0][3] ^= s[3][3];
        let t = s[3][3];
        s[3][3] = s[3][2];
        s[3][2] = s[3][1];
        s[3][1] = s[3][0];
        s[3][0] = t;
        s[0][0] ^= s[1][0] & s[2][0];
        s[0][1] ^= s[1][1] & s[2][1];
        s[0][2] ^= s[1][2] & s[2][2];
        s[0][3] ^= s[1][3] & s[2][3];
        s[0][0] = s[0][0].rotate_left(13);
        s[0][1] = s[0][1].rotate_left(13);
        s[0][2] = s[0][2].rotate_left(13);
        s[0][3] = s[0][3].rotate_left(13);

        s[1][0] ^= input[0];
        s[1][1] ^= input[1];
        s[1][2] ^= input[2];
        s[1][3] ^= input[3];
        s[1][0] ^= s[4][0];
        s[1][1] ^= s[4][1];
        s[1][2] ^= s[4][2];
        s[1][3] ^= s[4][3];
        s[4].swap(3, 1);
        s[4].swap(2, 0);
        s[1][0] ^= s[2][0] & s[3][0];
        s[1][1] ^= s[2][1] & s[3][1];
        s[1][2] ^= s[2][2] & s[3][2];
        s[1][3] ^= s[2][3] & s[3][3];
        s[1][0] = s[1][0].rotate_left(46);
        s[1][1] = s[1][1].rotate_left(46);
        s[1][2] = s[1][2].rotate_left(46);
        s[1][3] = s[1][3].rotate_left(46);

        s[2][0] ^= input[0];
        s[2][1] ^= input[1];
        s[2][2] ^= input[2];
        s[2][3] ^= input[3];
        s[2][0] ^= s[0][0];
        s[2][1] ^= s[0][1];
        s[2][2] ^= s[0][2];
        s[2][3] ^= s[0][3];
        let t = s[0][0];
        s[0][0] = s[0][1];
        s[0][1] = s[0][2];
        s[0][2] = s[0][3];
        s[0][3] = t;
        s[2][0] ^= s[3][0] & s[4][0];
        s[2][1] ^= s[3][1] & s[4][1];
        s[2][2] ^= s[3][2] & s[4][2];
        s[2][3] ^= s[3][3] & s[4][3];
        s[2][0] = s[2][0].rotate_left(38);
        s[2][1] = s[2][1].rotate_left(38);
        s[2][2] = s[2][2].rotate_left(38);
        s[2][3] = s[2][3].rotate_left(38);

        s[3][0] ^= input[0];
        s[3][1] ^= input[1];
        s[3][2] ^= input[2];
        s[3][3] ^= input[3];
        s[3][0] ^= s[1][0];
        s[3][1] ^= s[1][1];
        s[3][2] ^= s[1][2];
        s[3][3] ^= s[1][3];
        s[1].swap(3, 1);
        s[1].swap(2, 0);
        s[3][0] ^= s[4][0] & s[0][0];
        s[3][1] ^= s[4][1] & s[0][1];
        s[3][2] ^= s[4][2] & s[0][2];
        s[3][3] ^= s[4][3] & s[0][3];
        s[3][0] = s[3][0].rotate_left(7);
        s[3][1] = s[3][1].rotate_left(7);
        s[3][2] = s[3][2].rotate_left(7);
        s[3][3] = s[3][3].rotate_left(7);

        s[4][0] ^= input[0];
        s[4][1] ^= input[1];
        s[4][2] ^= input[2];
        s[4][3] ^= input[3];
        s[4][0] ^= s[2][0];
        s[4][1] ^= s[2][1];
        s[4][2] ^= s[2][2];
        s[4][3] ^= s[2][3];
        let t = s[2][3];
        s[2][3] = s[2][2];
        s[2][2] = s[2][1];
        s[2][1] = s[2][0];
        s[2][0] = t;
        s[4][0] ^= s[0][0] & s[1][0];
        s[4][1] ^= s[0][1] & s[1][1];
        s[4][2] ^= s[0][2] & s[1][2];
        s[4][3] ^= s[0][3] & s[1][3];
        s[4][0] = s[4][0].rotate_left(4);
        s[4][1] = s[4][1].rotate_left(4);
        s[4][2] = s[4][2].rotate_left(4);
        s[4][3] = s[4][3].rotate_left(4);
    }

    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let c = [
            0x0u8, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9,
            0x79, 0x62, 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42,
            0x73, 0xb5, 0x28, 0xdd,
        ];
        let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
        let mut state = State {
            s: [
                [
                    u64::from_le_bytes(nonce[0..8].try_into().unwrap()),
                    u64::from_le_bytes(nonce[8..16].try_into().unwrap()),
                    0,
                    0,
                ],
                [k0, k1, k0, k1],
                [!0, !0, !0, !0],
                [0, 0, 0, 0],
                [
                    u64::from_le_bytes(c[0..8].try_into().unwrap()),
                    u64::from_le_bytes(c[8..16].try_into().unwrap()),
                    u64::from_le_bytes(c[16..24].try_into().unwrap()),
                    u64::from_le_bytes(c[24..32].try_into().unwrap()),
                ],
            ],
        };
        for _ in 0..16 {
            state.update(&[0u64; 4]);
        }
        state.s[1][0] ^= k0;
        state.s[1][1] ^= k1;
        state.s[1][2] ^= k0;
        state.s[1][3] ^= k1;
        state
    }

    fn enc(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let p: [u64; 4] = [
            u64::from_le_bytes(src[0..8].try_into().unwrap()),
            u64::from_le_bytes(src[8..16].try_into().unwrap()),
            u64::from_le_bytes(src[16..24].try_into().unwrap()),
            u64::from_le_bytes(src[24..32].try_into().unwrap()),
        ];
        let c = {
            let s = &self.s;
            [
                p[0] ^ s[0][0] ^ s[1][1] ^ (s[2][0] & s[3][0]),
                p[1] ^ s[0][1] ^ s[1][2] ^ (s[2][1] & s[3][1]),
                p[2] ^ s[0][2] ^ s[1][3] ^ (s[2][2] & s[3][2]),
                p[3] ^ s[0][3] ^ s[1][0] ^ (s[2][3] & s[3][3]),
            ]
        };
        dst[0..8].copy_from_slice(&c[0].to_le_bytes());
        dst[8..16].copy_from_slice(&c[1].to_le_bytes());
        dst[16..24].copy_from_slice(&c[2].to_le_bytes());
        dst[24..32].copy_from_slice(&c[3].to_le_bytes());
        self.update(&p);
    }

    fn dec(&mut self, dst: &mut [u8; 32], src: &[u8; 32]) {
        let c: [u64; 4] = [
            u64::from_le_bytes(src[0..8].try_into().unwrap()),
            u64::from_le_bytes(src[8..16].try_into().unwrap()),
            u64::from_le_bytes(src[16..24].try_into().unwrap()),
            u64::from_le_bytes(src[24..32].try_into().unwrap()),
        ];
        let p = {
            let s = &self.s;
            [
                c[0] ^ s[0][0] ^ s[1][1] ^ (s[2][0] & s[3][0]),
                c[1] ^ s[0][1] ^ s[1][2] ^ (s[2][1] & s[3][1]),
                c[2] ^ s[0][2] ^ s[1][3] ^ (s[2][2] & s[3][2]),
                c[3] ^ s[0][3] ^ s[1][0] ^ (s[2][3] & s[3][3]),
            ]
        };
        dst[0..8].copy_from_slice(&p[0].to_le_bytes());
        dst[8..16].copy_from_slice(&p[1].to_le_bytes());
        dst[16..24].copy_from_slice(&p[2].to_le_bytes());
        dst[24..32].copy_from_slice(&p[3].to_le_bytes());
        self.update(&p);
    }

    fn dec_partial(&mut self, dst: &mut [u8; 32], src: &[u8]) {
        let len = src.len();
        let mut src_padded = [0u8; 32];
        src_padded[..len].copy_from_slice(src);
        let c: [u64; 4] = [
            u64::from_le_bytes(src_padded[0..8].try_into().unwrap()),
            u64::from_le_bytes(src_padded[8..16].try_into().unwrap()),
            u64::from_le_bytes(src_padded[16..24].try_into().unwrap()),
            u64::from_le_bytes(src_padded[24..32].try_into().unwrap()),
        ];
        let p = {
            let s = &self.s;
            [
                c[0] ^ s[0][0] ^ s[1][1] ^ (s[2][0] & s[3][0]),
                c[1] ^ s[0][1] ^ s[1][2] ^ (s[2][1] & s[3][1]),
                c[2] ^ s[0][2] ^ s[1][3] ^ (s[2][2] & s[3][2]),
                c[3] ^ s[0][3] ^ s[1][0] ^ (s[2][3] & s[3][3]),
            ]
        };
        dst[0..8].copy_from_slice(&p[0].to_le_bytes());
        dst[8..16].copy_from_slice(&p[1].to_le_bytes());
        dst[16..24].copy_from_slice(&p[2].to_le_bytes());
        dst[24..32].copy_from_slice(&p[3].to_le_bytes());
        dst[len..].fill(0);
        let p: [u64; 4] = [
            u64::from_le_bytes(dst[0..8].try_into().unwrap()),
            u64::from_le_bytes(dst[8..16].try_into().unwrap()),
            u64::from_le_bytes(dst[16..24].try_into().unwrap()),
            u64::from_le_bytes(dst[24..32].try_into().unwrap()),
        ];
        self.update(&p);
    }

    fn mac(&mut self, adlen: usize, mlen: usize) -> Tag {
        let t: [u64; 4] = [adlen as u64 * 8, mlen as u64 * 8, 0, 0];
        {
            let s = &mut self.s;
            s[4][0] ^= s[0][0];
            s[4][1] ^= s[0][1];
            s[4][2] ^= s[0][2];
            s[4][3] ^= s[0][3];
        }
        for _ in 0..10 {
            self.update(&t);
        }
        let s = &mut self.s;
        s[0][0] ^= s[1][1] ^ (s[2][0] & s[3][0]);
        s[0][1] ^= s[1][2] ^ (s[2][1] & s[3][1]);
        s[0][2] ^= s[1][3] ^ (s[2][2] & s[3][2]);
        s[0][3] ^= s[1][0] ^ (s[2][3] & s[3][3]);
        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&s[0][0].to_le_bytes());
        tag[8..16].copy_from_slice(&s[0][1].to_le_bytes());
        tag
    }
}

#[repr(transparent)]
pub struct Morus(State);

impl Morus {
    /// Create a new AEAD instance.
    /// `key` and `nonce` must be 16 bytes long.
    pub fn new(nonce: &Nonce, key: &Key) -> Self {
        Morus(State::new(key, nonce))
    }

    /// Encrypts a message using Morus-1280-128
    /// # Arguments
    /// * `m` - Message
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    #[cfg(feature = "std")]
    pub fn encrypt(mut self, m: &[u8], ad: &[u8]) -> (Vec<u8>, Tag) {
        let state = &mut self.0;
        let mlen = m.len();
        let adlen = ad.len();
        let mut c = Vec::with_capacity(mlen);
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let mut i = 0;
        while i + 32 <= adlen {
            src.copy_from_slice(&ad[i..][..32]);
            state.enc(&mut dst, &src);
            i += 32;
        }
        if adlen % 32 != 0 {
            src.fill(0);
            src[..adlen % 32].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 32 <= mlen {
            src.copy_from_slice(&m[i..][..32]);
            state.enc(&mut dst, &src);
            c.extend_from_slice(&dst);
            i += 32;
        }
        if mlen % 32 != 0 {
            src.fill(0);
            src[..mlen % 32].copy_from_slice(&m[i..]);
            state.enc(&mut dst, &src);
            c.extend_from_slice(&dst[..mlen % 32]);
        }
        let tag = state.mac(adlen, mlen);
        (c, tag)
    }

    /// Encrypts a message in-place using Morus-1280-128
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `ad` - Associated data
    /// # Returns
    /// Encrypted message and authentication tag.
    pub fn encrypt_in_place(mut self, mc: &mut [u8], ad: &[u8]) -> Tag {
        let state = &mut self.0;
        let mclen = mc.len();
        let adlen = ad.len();
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let mut i = 0;
        while i + 32 <= adlen {
            src.copy_from_slice(&ad[i..][..32]);
            state.enc(&mut dst, &src);
            i += 32;
        }
        if adlen % 32 != 0 {
            src.fill(0);
            src[..adlen % 32].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 32 <= mclen {
            src.copy_from_slice(&mc[i..][..32]);
            state.enc(&mut dst, &src);
            mc[i..][..32].copy_from_slice(&dst);
            i += 32;
        }
        if mclen % 32 != 0 {
            src.fill(0);
            src[..mclen % 32].copy_from_slice(&mc[i..]);
            state.enc(&mut dst, &src);
            mc[i..].copy_from_slice(&dst[..mclen % 32]);
        }

        state.mac(adlen, mclen)
    }

    /// Decrypts a message using Morus-1280-128
    /// # Arguments
    /// * `c` - Ciphertext
    /// * `tag` - Authentication tag
    /// * `ad` - Associated data
    /// # Returns
    /// Decrypted message.
    #[cfg(feature = "std")]
    pub fn decrypt(mut self, c: &[u8], tag: &Tag, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let state = &mut self.0;
        let clen = c.len();
        let adlen = ad.len();
        let mut m = Vec::with_capacity(clen);
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let mut i = 0;
        while i + 32 <= adlen {
            src.copy_from_slice(&ad[i..][..32]);
            state.enc(&mut dst, &src);
            i += 32;
        }
        if adlen % 32 != 0 {
            src.fill(0);
            src[..adlen % 32].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 32 <= clen {
            src.copy_from_slice(&c[i..][..32]);
            state.dec(&mut dst, &src);
            m.extend_from_slice(&dst);
            i += 32;
        }
        if clen % 32 != 0 {
            state.dec_partial(&mut dst, &c[i..]);
            m.extend_from_slice(&dst[0..clen % 32]);
        }
        let tag2 = state.mac(adlen, clen);
        let mut acc = 0;
        for (a, b) in tag.iter().zip(tag2.iter()) {
            acc |= a ^ b;
        }
        if acc != 0 {
            m.fill(0xaa);
            return Err(Error::InvalidTag);
        }
        Ok(m)
    }

    /// Decrypts a message in-place using Morus-1280-128
    /// # Arguments
    /// * `mc` - Input and output buffer
    /// * `tag` - Authentication tag
    /// * `ad` - Associated data
    pub fn decrypt_in_place(mut self, mc: &mut [u8], tag: &Tag, ad: &[u8]) -> Result<(), Error> {
        let state = &mut self.0;
        let mclen = mc.len();
        let adlen = ad.len();
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let mut i = 0;
        while i + 32 <= adlen {
            src.copy_from_slice(&ad[i..][..32]);
            state.enc(&mut dst, &src);
            i += 32;
        }
        if adlen % 32 != 0 {
            src.fill(0);
            src[..adlen % 32].copy_from_slice(&ad[i..]);
            state.enc(&mut dst, &src);
        }
        i = 0;
        while i + 32 <= mclen {
            src.copy_from_slice(&mc[i..][..32]);
            state.dec(&mut dst, &src);
            mc[i..][..32].copy_from_slice(&dst);
            i += 32;
        }
        if mclen % 32 != 0 {
            state.dec_partial(&mut dst, &mc[i..]);
            mc[i..].copy_from_slice(&dst[0..mclen % 32]);
        }
        let tag2 = state.mac(adlen, mclen);
        let mut acc = 0;
        for (a, b) in tag.iter().zip(tag2.iter()) {
            acc |= a ^ b;
        }
        if acc != 0 {
            mc.fill(0xaa);
            return Err(Error::InvalidTag);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Morus;

    #[test]
    #[cfg(feature = "std")]
    fn test_morus() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Morus::new(&nonce, key).encrypt(m, ad);
        let expected_c = [
            113, 42, 233, 132, 67, 60, 238, 160, 68, 138, 106, 79, 53, 175, 212, 107, 66, 244, 45,
            105, 49, 110, 66, 170, 84, 38, 77, 253, 137, 81, 41, 59, 110, 214, 118, 201, 168, 19,
            231, 244, 39, 69, 230, 33, 13, 233, 200, 44, 74, 198, 127, 222, 87, 105, 92, 45, 30,
            31, 47, 48, 38, 130, 241, 24, 198, 137, 89, 21, 222, 143, 166, 61, 225, 187, 121, 140,
            122, 23, 140, 227, 41, 13, 254, 53, 39, 195, 112, 164, 198, 91, 224, 28, 165, 91, 122,
            187, 38, 181, 115, 173, 233, 7, 108, 191, 155, 140, 6, 172, 199, 80, 71, 10, 69, 36,
        ];
        let expected_tag = [
            254, 11, 243, 234, 96, 11, 3, 85, 235, 83, 93, 221, 53, 50, 14, 27,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Morus::new(&nonce, key).decrypt(&c, &tag, ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_morus_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Morus::new(&nonce, key).encrypt_in_place(&mut mc, ad);
        let expected_mc = [
            113, 42, 233, 132, 67, 60, 238, 160, 68, 138, 106, 79, 53, 175, 212, 107, 66, 244, 45,
            105, 49, 110, 66, 170, 84, 38, 77, 253, 137, 81, 41, 59, 110, 214, 118, 201, 168, 19,
            231, 244, 39, 69, 230, 33, 13, 233, 200, 44, 74, 198, 127, 222, 87, 105, 92, 45, 30,
            31, 47, 48, 38, 130, 241, 24, 198, 137, 89, 21, 222, 143, 166, 61, 225, 187, 121, 140,
            122, 23, 140, 227, 41, 13, 254, 53, 39, 195, 112, 164, 198, 91, 224, 28, 165, 91, 122,
            187, 38, 181, 115, 173, 233, 7, 108, 191, 155, 140, 6, 172, 199, 80, 71, 10, 69, 36,
        ];
        let expected_tag = [
            254, 11, 243, 234, 96, 11, 3, 85, 235, 83, 93, 221, 53, 50, 14, 27,
        ];
        assert_eq!(mc, expected_mc);
        assert_eq!(tag, expected_tag);

        Morus::new(&nonce, key)
            .decrypt_in_place(&mut mc, &tag, ad)
            .unwrap();
        assert_eq!(mc, m);
    }
}
