use std::iter::{Sum};
use std::ops::{Add,AddAssign,Not};
use std::fmt;

pub trait UnsignedInt: Copy+Eq+From<u8>+Not<Output=Self>+fmt::Octal+fmt::LowerHex+fmt::UpperHex+fmt::Binary+fmt::Display {
	fn overflowing_add(self, other: Self) -> (Self, bool);
	fn checked_add(self, other: Self) -> Option<Self>;
	fn wrapping_add(self, other: Self) -> Self;
}

macro_rules! impl_unsignedint {
	($t:ty) => (
		impl UnsignedInt for $t {
			fn overflowing_add(self, other: Self) -> (Self, bool) {
				Self::overflowing_add(self, other)
			}

			fn checked_add(self, other: Self) -> Option<Self> {
				Self::checked_add(self, other)
			}

			fn wrapping_add(self, other: Self) -> Self {
				Self::wrapping_add(self, other)
			}
		}
	);
}

impl_unsignedint!{u8}
impl_unsignedint!{u16}
impl_unsignedint!{u32}
impl_unsignedint!{u64}
impl_unsignedint!{usize}

#[derive(Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Hash,Debug)]
pub struct OneComplement<U: UnsignedInt> {
	inner: U,
}

impl<U: UnsignedInt> OneComplement<U> {
	pub fn add(self, b: Self) -> Self {
		match self.inner.overflowing_add(b.inner) {
			(res, false) => OneComplement{inner: res},
			// (res, true) => OneComplement{inner: res.checked_add(U::from(1)).unwrap()},
			// overflow correction should never overflow itself
			(res, true) => OneComplement{inner: res.wrapping_add(U::from(1))},
		}
	}

	pub fn not(self) -> Self {
		OneComplement{inner: self.inner.not()}
	}

	pub fn into_inner(self) -> U {
		self.inner
	}
}

impl<U: UnsignedInt> Default for OneComplement<U> {
	fn default() -> Self {
		OneComplement{inner: U::from(0)}
	}
}

impl<U: UnsignedInt> From<U> for OneComplement<U> {
	fn from(u: U) -> Self {
		OneComplement{inner: u}
	}
}

impl<U: UnsignedInt> Add<OneComplement<U>> for OneComplement<U> {
	type Output = OneComplement<U>;
	fn add(self, other: OneComplement<U>) -> OneComplement<U> {
		OneComplement::add(self, other)
	}
}
impl<'a, U: UnsignedInt> Add<OneComplement<U>> for &'a OneComplement<U> {
	type Output = OneComplement<U>;
	fn add(self, other: OneComplement<U>) -> OneComplement<U> {
		OneComplement::add(*self, other)
	}
}
impl<'a, U: UnsignedInt> Add<&'a OneComplement<U>> for OneComplement<U> {
	type Output = OneComplement<U>;
	fn add(self, other: &'a OneComplement<U>) -> OneComplement<U> {
		OneComplement::add(self, *other)
	}
}
impl<'a, 'b, U: UnsignedInt> Add<&'a OneComplement<U>> for &'b OneComplement<U> {
	type Output = OneComplement<U>;
	fn add(self, other: &'a OneComplement<U>) -> OneComplement<U> {
		OneComplement::add(*self, *other)
	}
}
impl<U: UnsignedInt> Not for OneComplement<U> {
	type Output = OneComplement<U>;
	fn not(self) -> Self::Output {
		OneComplement::not(self)
	}
}
impl<'a, U: UnsignedInt> Not for &'a OneComplement<U> {
	type Output = OneComplement<U>;
	fn not(self) -> Self::Output {
		OneComplement::not(*self)
	}
}
impl<U: UnsignedInt> AddAssign<OneComplement<U>> for OneComplement<U> {
	fn add_assign(&mut self, other: OneComplement<U>) {
		*self = OneComplement::add(*self, other);
	}
}

impl<U: UnsignedInt> fmt::Display for OneComplement<U> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(&self.inner, f)
	}
}

impl<U: UnsignedInt> fmt::Octal for OneComplement<U> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Octal::fmt(&self.inner, f)
	}
}

impl<U: UnsignedInt> fmt::LowerHex for OneComplement<U> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::LowerHex::fmt(&self.inner, f)
	}
}

impl<U: UnsignedInt> fmt::UpperHex for OneComplement<U> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::UpperHex::fmt(&self.inner, f)
	}
}

impl<U: UnsignedInt> fmt::Binary for OneComplement<U> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Binary::fmt(&self.inner, f)
	}
}

impl<U: UnsignedInt> Sum<OneComplement<U>> for OneComplement<U> {
	fn sum<I>(iter: I) -> OneComplement<U>
	where I: Iterator<Item=OneComplement<U>> {
		iter.fold(Default::default(), |acc, x| acc + x)
	}
}

impl<'a, U: UnsignedInt> Sum<&'a OneComplement<U>> for OneComplement<U> {
	fn sum<I>(iter: I) -> OneComplement<U> 
	where I: Iterator<Item=&'a OneComplement<U>> {
		iter.fold(Default::default(), |acc, x| acc + x)
	}
}
