pub mod onecomplement;

/* RFC 1071 16-bit checksum by one-complement sum ("mod (2^16-1)") */

pub use self::onecomplement::OneComplement;

trait FoldCSum: onecomplement::UnsignedInt {
	fn fold_csum(self) -> u16;
}

impl FoldCSum for u16 {
	fn fold_csum(self) -> u16 {
		self
	}
}

fn fold_csum_u32(u: u32) -> u16 {
	let a = (u >> 16) as u16;
	let b = u as u16;
	match a.overflowing_add(b) {
		(res, false) => res,
		(res, true) => res+1, // can't overflow again
	}
}

fn fold_csum_u64(u: u64) -> u16 {
	let a = (u >> 32) as u32;
	let b = u as u32;
	fold_csum_u32(match a.overflowing_add(b) {
		(res, false) => res,
		(res, true) => res+1, // can't overflow again
	})
}

impl FoldCSum for u32 {
	fn fold_csum(self) -> u16 {
		fold_csum_u32(self)
	}
}

impl FoldCSum for u64 {
	fn fold_csum(self) -> u16 {
		fold_csum_u64(self)
	}
}

// read some value of primitive type and forward buffer; returns None if
// buffer is too small
fn read_native_and_fwd<T: Default>(data: &mut &[u8]) -> Option<T> {
	use std::mem::size_of;
	use std::ptr::copy_nonoverlapping;
	let s = size_of::<T>();
	if data.len() >= s {
		let mut value: T = Default::default();
		unsafe {
			copy_nonoverlapping(
				data.as_ptr(),
				&mut value as *mut T as *mut u8,
				size_of::<T>());
		}
		*data = &(*data)[size_of::<T>()..];
		Some(value)
	} else {
		None
	}
}

pub mod traits {
	pub trait CSum: Default+Clone+Copy {
		fn new() -> Self;
		fn result(self) -> u16;
		fn add(self, data: &[u8]) -> Self;
	}
}

macro_rules! define_csum_with {
	($name:ident, $with:ty) => (
		#[derive(Default,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
		pub struct $name {
			odd_position: bool,
			inner: OneComplement<$with>,
		}

		impl $name {
			pub fn new() -> $name {
				Default::default()
			}

			pub fn result(self) -> u16 {
				self.inner.into_inner().fold_csum()
			}

			pub fn add(self, mut data: &[u8]) -> Self {
				if data.len() == 0 { return self; }
				let mut csum = self;
				if csum.odd_position {
					csum.inner += OneComplement::from((data[0] as $with) << 8);
					data = &data[1..];
					csum.odd_position = false;
				}
				while let Some(value) = read_native_and_fwd::<$with>(&mut data) {
					csum.inner += OneComplement::from(value);
				}
				// now data.len() is < size_of::<$with>(); i.e. the
				// following read_native_and_fwd operations can only
				// succeed for types T with size_of::<T> <
				// size_of::<$with>; casting to $with therefore never
				// looses any data.
				if let Some(value) = read_native_and_fwd::<u64>(&mut data) {
					csum.inner += OneComplement::from(value as $with);
				}
				if let Some(value) = read_native_and_fwd::<u32>(&mut data) {
					csum.inner += OneComplement::from(value as $with);
				}
				if let Some(value) = read_native_and_fwd::<u16>(&mut data) {
					csum.inner += OneComplement::from(value as $with);
				}
				if let Some(value) = read_native_and_fwd::<u8>(&mut data) {
					csum.inner += OneComplement::from(value as $with);
					csum.odd_position = true;
				}
				assert_eq!(data.len(), 0);
				csum
			}
		}

		impl traits::CSum for $name {
			fn new() -> Self {
				$name::new()
			}
			fn result(self) -> u16 {
				$name::result(self)
			}
			fn add(self, data: &[u8]) -> Self {
				$name::add(self, data)
			}
		}
	);
}

type CSumDefaultType = u64;

define_csum_with!{CSum, CSumDefaultType}
/* so we can test all variants */
define_csum_with!{CSum16, u16}
define_csum_with!{CSum32, u32}
define_csum_with!{CSum64, u64}

#[cfg(test)]
mod test {
	use super::*;
	use super::{read_native_and_fwd};

	fn read_native_slice<T: Default>(mut slice: &[u8]) -> T {
		read_native_and_fwd(&mut slice).unwrap()
	}

	fn rfc1071_section3_with<T: traits::CSum>() {
		let input : [u8; 8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
		// compare big-endian result to expected number
		assert_eq!(T::new().add(&input[..]).result().to_be(), 0xddf2);

		// use native endianess
		assert_eq!(T::new().add(&input[..]).result(), read_native_slice(&[0xdd, 0xf2][..]));
	}

	fn rfc1071_section3_split_with<T: traits::CSum>() {
		let input1 : [u8; 3] = [0x00, 0x01, 0xf2];
		let input2 : [u8; 5] = [0x03, 0xf4, 0xf5, 0xf6, 0xf7];
		// compare big-endian result to expected number
		assert_eq!(T::new().add(&input1[..]).add(&input2[..]).result().to_be(), 0xddf2);

		// use native endianess
		assert_eq!(T::new().add(&input1[..]).add(&input2[..]).result(), read_native_slice(&[0xdd, 0xf2][..]));
	}

	#[test]
	fn rfc1071_section3() {
		rfc1071_section3_with::<CSum>();
	}

	#[test]
	fn rfc1071_section3_u16() {
		rfc1071_section3_with::<CSum16>();
	}

	#[test]
	fn rfc1071_section3_u32() {
		rfc1071_section3_with::<CSum32>();
	}

	#[test]
	fn rfc1071_section3_u64() {
		rfc1071_section3_with::<CSum64>();
	}

	#[test]
	fn rfc1071_section3_split() {
		rfc1071_section3_split_with::<CSum>();
	}

	#[test]
	fn rfc1071_section3_split_u16() {
		rfc1071_section3_split_with::<CSum16>();
	}

	#[test]
	fn rfc1071_section3_split_u32() {
		rfc1071_section3_split_with::<CSum32>();
	}

	#[test]
	fn rfc1071_section3_split_u64() {
		rfc1071_section3_split_with::<CSum64>();
	}
}
