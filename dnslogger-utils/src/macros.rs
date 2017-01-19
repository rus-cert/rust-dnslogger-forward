#[macro_export]
macro_rules! try_wrap_err {
	($f:expr, $data:expr) => (
		match $data {
			Ok(res) => res,
			Err(e) => return Err($f(e)),
		}
	);
}

/* Gives the handler $f a chance to convert the error into success or
 * another error; in any case the function stops here.
 */
#[macro_export]
macro_rules! try_handle_err {
	($f:expr, $data:expr) => (
		match $data {
			Ok(res) => res,
			Err(e) => return $f(e),
		}
	);
}

#[macro_export]
macro_rules! try_option {
	($data:expr) => (
		match $data {
			Some(res) => res,
			None => return None,
		}
	);
}
