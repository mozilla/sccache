use std::cmp::Ordering;
use std::error::Error;
use std::ffi::OsString;
use std::fmt::{self, Debug, Display};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::str;

pub type ArgParseResult<T> = StdResult<T, ArgParseError>;
pub type ArgToStringResult = StdResult<String, ArgToStringError>;
pub type PathTransformerFn<'a> = &'a mut dyn FnMut(&Path) -> Option<String>;

#[derive(Debug, PartialEq, Eq)]
pub enum ArgParseError {
    UnexpectedEndOfArgs,
    InvalidUnicode(OsString),
    Other(&'static str),
}

impl Display for ArgParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ArgParseError::UnexpectedEndOfArgs => "Unexpected end of args".into(),
            ArgParseError::InvalidUnicode(s) => format!("String {:?} contained invalid unicode", s),
            ArgParseError::Other(s) => format!("Arg-specific parsing failed: {}", s),
        };
        write!(f, "{}", s)
    }
}

impl Error for ArgParseError {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArgToStringError {
    FailedPathTransform(PathBuf),
    InvalidUnicode(OsString),
}

impl Display for ArgToStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ArgToStringError::FailedPathTransform(p) => {
                format!("Path {:?} could not be transformed", p)
            }
            ArgToStringError::InvalidUnicode(s) => {
                format!("String {:?} contained invalid unicode", s)
            }
        };
        write!(f, "{}", s)
    }
}

impl Error for ArgToStringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub type Delimiter = Option<u8>;

/// Representation of a parsed argument
/// The type parameter T contains the parsed information for this argument,
/// for use during argument handling (typically an enum to allow switching
/// on the different kinds of argument). `Flag`s may contain a simple
/// variant which influences how to do caching, whereas `WithValue`s could
/// be a struct variant with parsed data from the value.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Argument<T> {
    /// Unknown non-flag argument ; e.g. "foo"
    Raw(OsString),
    /// Unknown flag argument ; e.g. "-foo"
    UnknownFlag(OsString),
    /// Known flag argument ; e.g. "-bar"
    Flag(&'static str, T),
    /// Known argument with a value ; e.g. "-qux bar", where the way the
    /// value is passed is described by the ArgDisposition type.
    WithValue(&'static str, T, ArgDisposition),
}

/// How a value is passed to an argument with a value.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ArgDisposition {
    /// As "-arg value"
    Separated,
    /// As "-arg value", but "-arg<delimiter>value" would be valid too
    CanBeConcatenated(Delimiter),
    /// As "-arg<delimiter>value", but "-arg value" would be valid too
    CanBeSeparated(Delimiter),
    /// As "-arg<delimiter>value"
    Concatenated(Delimiter),
}

pub enum NormalizedDisposition {
    Separated,
    Concatenated,
}

impl<T: ArgumentValue> Argument<T> {
    /// For arguments that allow both a concatenated or separated disposition,
    /// normalize a parsed argument to a preferred disposition.
    pub fn normalize(self, disposition: NormalizedDisposition) -> Self {
        match self {
            Argument::WithValue(s, v, ArgDisposition::CanBeConcatenated(d))
            | Argument::WithValue(s, v, ArgDisposition::CanBeSeparated(d)) => Argument::WithValue(
                s,
                v,
                match disposition {
                    NormalizedDisposition::Separated => ArgDisposition::Separated,
                    NormalizedDisposition::Concatenated => ArgDisposition::Concatenated(d),
                },
            ),
            a => a,
        }
    }

    pub fn to_os_string(&self) -> OsString {
        match *self {
            Argument::Raw(ref s) | Argument::UnknownFlag(ref s) => s.clone(),
            Argument::Flag(ref s, _) | Argument::WithValue(ref s, _, _) => s.into(),
        }
    }

    pub fn flag_str(&self) -> Option<&'static str> {
        match *self {
            Argument::Flag(s, _) | Argument::WithValue(s, _, _) => Some(s),
            _ => None,
        }
    }

    pub fn get_data(&self) -> Option<&T> {
        match *self {
            Argument::Flag(_, ref d) => Some(d),
            Argument::WithValue(_, ref d, _) => Some(d),
            _ => None,
        }
    }

    /// Transforms a parsed argument into an iterator.
    pub fn iter_os_strings(&self) -> Iter<'_, T> {
        Iter {
            arg: self,
            emitted: 0,
        }
    }

    /// Transforms a parsed argument into an iterator over strings, with transformed paths.
    #[cfg(feature = "dist-client")]
    pub fn iter_strings<F: FnMut(&Path) -> Option<String>>(
        &self,
        path_transformer: F,
    ) -> IterStrings<'_, T, F> {
        IterStrings {
            arg: self,
            emitted: 0,
            path_transformer,
        }
    }
}

pub struct Iter<'a, T> {
    arg: &'a Argument<T>,
    emitted: usize,
}

impl<'a, T: ArgumentValue> Iterator for Iter<'a, T> {
    type Item = OsString;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match *self.arg {
            Argument::Raw(ref s) | Argument::UnknownFlag(ref s) => match self.emitted {
                0 => Some(s.clone()),
                _ => None,
            },
            Argument::Flag(s, _) => match self.emitted {
                0 => Some(s.into()),
                _ => None,
            },
            Argument::WithValue(s, ref v, ref d) => match (self.emitted, d) {
                (0, &ArgDisposition::CanBeSeparated(d)) | (0, &ArgDisposition::Concatenated(d)) => {
                    let mut s = OsString::from(s);
                    let v = v.clone().into_arg_os_string();
                    if let Some(d) = d {
                        if !v.is_empty() {
                            s.push(OsString::from(
                                str::from_utf8(&[d]).expect("delimiter should be ascii"),
                            ));
                        }
                    }
                    s.push(v);
                    Some(s)
                }
                (0, &ArgDisposition::Separated) | (0, &ArgDisposition::CanBeConcatenated(_)) => {
                    Some(s.into())
                }
                (1, &ArgDisposition::Separated) | (1, &ArgDisposition::CanBeConcatenated(_)) => {
                    Some(v.clone().into_arg_os_string())
                }
                _ => None,
            },
        };
        if result.is_some() {
            self.emitted += 1;
        }
        result
    }
}

#[cfg(feature = "dist-client")]
pub struct IterStrings<'a, T, F> {
    arg: &'a Argument<T>,
    emitted: usize,
    path_transformer: F,
}

#[cfg(feature = "dist-client")]
impl<'a, T: ArgumentValue, F: FnMut(&Path) -> Option<String>> Iterator for IterStrings<'a, T, F> {
    type Item = ArgToStringResult;

    fn next(&mut self) -> Option<Self::Item> {
        let result: Option<Self::Item> = match *self.arg {
            Argument::Raw(ref s) | Argument::UnknownFlag(ref s) => match self.emitted {
                0 => Some(s.clone().into_arg_string(&mut self.path_transformer)),
                _ => None,
            },
            Argument::Flag(s, _) => match self.emitted {
                0 => Some(Ok(s.to_owned())),
                _ => None,
            },
            Argument::WithValue(s, ref v, ref d) => match (self.emitted, d) {
                (0, &ArgDisposition::CanBeSeparated(d)) | (0, &ArgDisposition::Concatenated(d)) => {
                    let mut s = s.to_owned();
                    let v = match v.clone().into_arg_string(&mut self.path_transformer) {
                        Ok(s) => s,
                        Err(e) => return Some(Err(e)),
                    };
                    if let Some(d) = d {
                        if !v.is_empty() {
                            s.push_str(str::from_utf8(&[d]).expect("delimiter should be ascii"));
                        }
                    }
                    s.push_str(&v);
                    Some(Ok(s))
                }
                (0, &ArgDisposition::Separated) | (0, &ArgDisposition::CanBeConcatenated(_)) => {
                    Some(Ok(s.to_owned()))
                }
                (1, &ArgDisposition::Separated) | (1, &ArgDisposition::CanBeConcatenated(_)) => {
                    Some(v.clone().into_arg_string(&mut self.path_transformer))
                }
                _ => None,
            },
        };
        if result.is_some() {
            self.emitted += 1;
        }
        result
    }
}

macro_rules! ArgData {
    // Collected all the arms, time to create the match
    { __matchify $var:ident $fn:ident ($( $fnarg:ident )*) ($( $arms:tt )*) } => {
        match $var {
            $( $arms )*
        }
    };
    // Unit variant
    { __matchify $var:ident $fn:ident ($( $fnarg:ident )*) ($( $arms:tt )*) $x:ident, $( $rest:tt )* } => {
        ArgData!{
            __matchify $var $fn ($($fnarg)*)
            ($($arms)* ArgData::$x => ().$fn($( $fnarg )*),)
            $($rest)*
        }
    };
    // Tuple variant
    { __matchify $var:ident $fn:ident ($( $fnarg:ident )*) ($( $arms:tt )*) $x:ident($y:ty), $( $rest:tt )* } => {
        ArgData!{
            __matchify $var $fn ($($fnarg)*)
            ($($arms)* ArgData::$x(inner) => inner.$fn($( $fnarg )*),)
            $($rest)*
        }
    };

    { __impl $( $tok:tt )+ } => {
        impl IntoArg for ArgData {
            fn into_arg_os_string(self) -> OsString {
                ArgData!{ __matchify self into_arg_os_string () () $($tok)+ }
            }
            fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
                ArgData!{ __matchify self into_arg_string (transformer) () $($tok)+ }
            }
        }
    };

    // PartialEq necessary for tests
    { pub $( $tok:tt )+ } => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum ArgData {
            $($tok)+
        }
        ArgData!{ __impl $( $tok )+ }
    };
    { $( $tok:tt )+ } => {
        #[derive(Clone, Debug, PartialEq)]
        #[allow(clippy::enum_variant_names)]
        enum ArgData {
            $($tok)+
        }
        ArgData!{ __impl $( $tok )+ }
    };
}

// The value associated with a parsed argument
pub trait ArgumentValue: IntoArg + Clone + Debug {}

impl<T: IntoArg + Clone + Debug> ArgumentValue for T {}

pub trait FromArg: Sized {
    fn process(arg: OsString) -> ArgParseResult<Self>;
}

pub trait IntoArg: Sized {
    fn into_arg_os_string(self) -> OsString;
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult;
}

impl FromArg for OsString {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        Ok(arg)
    }
}
impl FromArg for PathBuf {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        Ok(arg.into())
    }
}
impl FromArg for String {
    fn process(arg: OsString) -> ArgParseResult<Self> {
        arg.into_string().map_err(ArgParseError::InvalidUnicode)
    }
}

impl IntoArg for OsString {
    fn into_arg_os_string(self) -> OsString {
        self
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        self.into_string().map_err(ArgToStringError::InvalidUnicode)
    }
}
impl IntoArg for PathBuf {
    fn into_arg_os_string(self) -> OsString {
        self.into()
    }
    fn into_arg_string(self, transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        transformer(&self).ok_or(ArgToStringError::FailedPathTransform(self))
    }
}
impl IntoArg for String {
    fn into_arg_os_string(self) -> OsString {
        self.into()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        Ok(self)
    }
}
impl IntoArg for () {
    fn into_arg_os_string(self) -> OsString {
        OsString::new()
    }
    fn into_arg_string(self, _transformer: PathTransformerFn<'_>) -> ArgToStringResult {
        Ok(String::new())
    }
}

pub fn split_os_string_arg(val: OsString, split: &str) -> ArgParseResult<(String, Option<String>)> {
    let val = val.into_string().map_err(ArgParseError::InvalidUnicode)?;
    let mut split_it = val.splitn(2, split);
    let s1 = split_it.next().expect("splitn with no values");
    let maybe_s2 = split_it.next();
    Ok((s1.to_owned(), maybe_s2.map(|s| s.to_owned())))
}

/// The description of how an argument may be parsed
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ArgInfo<T> {
    /// An simple flag argument, of the form "-foo"
    Flag(&'static str, T),
    /// An argument with a value ; e.g. "-qux bar", where the way the
    /// value is passed is described by the ArgDisposition type.
    TakeArg(
        &'static str,
        fn(OsString) -> ArgParseResult<T>,
        ArgDisposition,
    ),
}

impl<T: ArgumentValue> ArgInfo<T> {
    /// Transform an argument description into a parsed Argument, given a
    /// string. For arguments with a value, where the value is separate, the
    /// `get_next_arg` function returns the next argument, in raw `OsString`
    /// form.
    fn process<F>(self, arg: &str, get_next_arg: F) -> ArgParseResult<Argument<T>>
    where
        F: FnOnce() -> Option<OsString>,
    {
        Ok(match self {
            ArgInfo::Flag(s, variant) => {
                debug_assert_eq!(s, arg);
                Argument::Flag(s, variant)
            }
            ArgInfo::TakeArg(s, create, ArgDisposition::Separated) => {
                debug_assert_eq!(s, arg);
                if let Some(a) = get_next_arg() {
                    Argument::WithValue(s, create(a)?, ArgDisposition::Separated)
                } else {
                    return Err(ArgParseError::UnexpectedEndOfArgs);
                }
            }
            ArgInfo::TakeArg(s, create, ArgDisposition::Concatenated(d)) => {
                let mut len = s.len();
                debug_assert_eq!(&arg[..len], s);
                if let Some(d) = d {
                    if arg.as_bytes().get(len) == Some(&d) {
                        len += 1;
                    }
                }
                Argument::WithValue(
                    s,
                    create(arg[len..].into())?,
                    ArgDisposition::Concatenated(d),
                )
            }
            ArgInfo::TakeArg(s, create, ArgDisposition::CanBeSeparated(d))
            | ArgInfo::TakeArg(s, create, ArgDisposition::CanBeConcatenated(d)) => {
                let derived = if arg == s {
                    ArgInfo::TakeArg(s, create, ArgDisposition::Separated)
                } else {
                    ArgInfo::TakeArg(s, create, ArgDisposition::Concatenated(d))
                };
                match derived.process(arg, get_next_arg) {
                    Err(ArgParseError::UnexpectedEndOfArgs) if d.is_none() => {
                        Argument::WithValue(s, create("".into())?, ArgDisposition::Concatenated(d))
                    }
                    Ok(Argument::WithValue(s, v, ArgDisposition::Concatenated(d))) => {
                        Argument::WithValue(s, v, ArgDisposition::CanBeSeparated(d))
                    }
                    Ok(Argument::WithValue(s, v, ArgDisposition::Separated)) => {
                        Argument::WithValue(s, v, ArgDisposition::CanBeConcatenated(d))
                    }
                    a => a?,
                }
            }
        })
    }

    /// Returns whether the given string matches the argument description, and if not,
    /// how it differs.
    fn cmp(&self, arg: &str) -> Ordering {
        match self {
            &ArgInfo::TakeArg(s, _, ArgDisposition::CanBeSeparated(None))
            | &ArgInfo::TakeArg(s, _, ArgDisposition::Concatenated(None))
                if arg.starts_with(s) =>
            {
                Ordering::Equal
            }
            &ArgInfo::TakeArg(s, _, ArgDisposition::CanBeSeparated(Some(d)))
            | &ArgInfo::TakeArg(s, _, ArgDisposition::Concatenated(Some(d)))
                if arg.len() > s.len() && arg.starts_with(s) =>
            {
                arg.as_bytes()[s.len()].cmp(&d)
            }
            _ => self.flag_str().cmp(arg),
        }
    }

    fn flag_str(&self) -> &'static str {
        match self {
            &ArgInfo::Flag(s, _) | &ArgInfo::TakeArg(s, _, _) => s,
        }
    }
}

/// Binary search for a `key` in a sorted array of items, given a comparison
/// function. This implementation is tweaked to handle the case where the
/// comparison function does prefix matching, where multiple items in the array
/// might match, but the last match is the one actually matching.
fn bsearch<K, T, F>(key: K, items: &[T], cmp: F) -> Option<&T>
where
    F: Fn(&T, &K) -> Ordering,
{
    let mut slice = items;
    while !slice.is_empty() {
        let middle = slice.len() / 2;
        match cmp(&slice[middle], &key) {
            Ordering::Equal => {
                let found_after = if slice.len() == 1 {
                    None
                } else {
                    bsearch(key, &slice[middle + 1..], cmp)
                };
                return found_after.or(Some(&slice[middle]));
            }
            Ordering::Greater => {
                slice = &slice[..middle];
            }
            Ordering::Less => {
                slice = &slice[middle + 1..];
            }
        }
    }
    None
}

/// Trait for generically search over a "set" of ArgInfos.
pub trait SearchableArgInfo<T> {
    fn search(&self, key: &str) -> Option<&ArgInfo<T>>;

    #[cfg(debug_assertions)]
    fn check(&self) -> bool;
}

/// Allow to search over a sorted array of ArgInfo items associated with extra
/// data.
impl<T: ArgumentValue> SearchableArgInfo<T> for &'static [ArgInfo<T>] {
    fn search(&self, key: &str) -> Option<&ArgInfo<T>> {
        bsearch(key, self, |i, k| i.cmp(k))
    }

    #[cfg(debug_assertions)]
    fn check(&self) -> bool {
        self.windows(2).all(|w| {
            let a = w[0].flag_str();
            let b = w[1].flag_str();
            assert!(a < b, "{} can't precede {}", a, b);
            true
        })
    }
}

/// Allow to search over a couple of arrays of ArgInfo, where the second
/// complements or overrides the first one.
impl<T: ArgumentValue> SearchableArgInfo<T> for (&'static [ArgInfo<T>], &'static [ArgInfo<T>]) {
    fn search(&self, key: &str) -> Option<&ArgInfo<T>> {
        match (self.0.search(key), self.1.search(key)) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => {
                if a.flag_str() > b.flag_str() {
                    Some(a)
                } else {
                    Some(b)
                }
            }
        }
    }

    #[cfg(debug_assertions)]
    fn check(&self) -> bool {
        self.0.check() && self.1.check()
    }
}

/// An `Iterator` for parsed arguments
pub struct ArgsIter<I, T, S>
where
    I: Iterator<Item = OsString>,
    S: SearchableArgInfo<T>,
{
    arguments: I,
    arg_info: S,
    seen_double_dashes: Option<bool>,
    phantom: PhantomData<T>,
}

impl<I, T, S> ArgsIter<I, T, S>
where
    I: Iterator<Item = OsString>,
    T: ArgumentValue,
    S: SearchableArgInfo<T>,
{
    /// Create an `Iterator` for parsed arguments, given an iterator of raw
    /// `OsString` arguments, and argument descriptions.
    pub fn new(arguments: I, arg_info: S) -> Self {
        #[cfg(debug_assertions)]
        debug_assert!(arg_info.check());
        ArgsIter {
            arguments,
            arg_info,
            seen_double_dashes: None,
            phantom: PhantomData,
        }
    }

    pub fn with_double_dashes(mut self) -> Self {
        self.seen_double_dashes = Some(false);
        self
    }
}

impl<I, T, S> Iterator for ArgsIter<I, T, S>
where
    I: Iterator<Item = OsString>,
    T: ArgumentValue,
    S: SearchableArgInfo<T>,
{
    type Item = ArgParseResult<Argument<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(arg) = self.arguments.next() {
            if let Some(seen_double_dashes) = &mut self.seen_double_dashes {
                if !*seen_double_dashes && arg == "--" {
                    *seen_double_dashes = true;
                }
                if *seen_double_dashes {
                    return Some(Ok(Argument::Raw(arg)));
                }
            }
            let s = arg.to_string_lossy();
            let arguments = &mut self.arguments;
            Some(match self.arg_info.search(&s[..]) {
                Some(i) => i.clone().process(&s[..], || arguments.next()),
                None => Ok(if s.starts_with('-') {
                    Argument::UnknownFlag(arg.clone())
                } else {
                    Argument::Raw(arg.clone())
                }),
            })
        } else {
            None
        }
    }
}

/// Helper macro used to define ArgInfo::Flag's.
/// Variant is an enum variant, e.g. enum ArgType { Variant }
///     flag!("-foo", Variant)
macro_rules! flag {
    ($s:expr, $variant:expr) => {
        ArgInfo::Flag($s, $variant)
    };
}

/// Helper macro used to define ArgInfo::TakeArg's.
/// Variant is an enum variant, e.g. enum ArgType { Variant(OsString) }
///     take_arg!("-foo", OsString, Separated, Variant)
///     take_arg!("-foo", OsString, Concatenated, Variant)
///     take_arg!("-foo", OsString, Concatenated('='), Variant)
macro_rules! take_arg {
    ($s:expr, $vtype:ident, Separated, $variant:expr) => {
        ArgInfo::TakeArg(
            $s,
            |arg: OsString| $vtype::process(arg).map($variant),
            ArgDisposition::Separated,
        )
    };
    ($s:expr, $vtype:ident, $d:ident, $variant:expr) => {
        ArgInfo::TakeArg(
            $s,
            |arg: OsString| $vtype::process(arg).map($variant),
            ArgDisposition::$d(None),
        )
    };
    ($s:expr, $vtype:ident, $d:ident($x:expr), $variant:expr) => {
        ArgInfo::TakeArg(
            $s,
            |arg: OsString| $vtype::process(arg).map($variant),
            ArgDisposition::$d(Some($x as u8)),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::{diff_with, Diff};
    use std::iter::FromIterator;

    macro_rules! arg {
        ($name:ident($x:expr)) => {
            Argument::$name($x.into())
        };

        ($name:ident($x:expr, $v:ident)) => {
            Argument::$name($x.into(), $v)
        };
        ($name:ident($x:expr, $v:ident($y:expr))) => {
            Argument::$name($x.into(), $v($y.into()))
        };
        ($name:ident($x:expr, $v:ident($y:expr), Separated)) => {
            Argument::$name($x, $v($y.into()), ArgDisposition::Separated)
        };
        ($name:ident($x:expr, $v:ident($y:expr), $d:ident)) => {
            Argument::$name($x, $v($y.into()), ArgDisposition::$d(None))
        };
        ($name:ident($x:expr, $v:ident($y:expr), $d:ident($z:expr))) => {
            Argument::$name($x, $v($y.into()), ArgDisposition::$d(Some($z as u8)))
        };

        ($name:ident($x:expr, $v:ident::$w:ident)) => {
            Argument::$name($x.into(), $v::$w)
        };
        ($name:ident($x:expr, $v:ident::$w:ident($y:expr))) => {
            Argument::$name($x.into(), $v::$w($y.into()))
        };
        ($name:ident($x:expr, $v:ident::$w:ident($y:expr), Separated)) => {
            Argument::$name($x, $v::$w($y.into()), ArgDisposition::Separated)
        };
        ($name:ident($x:expr, $v:ident::$w:ident($y:expr), $d:ident)) => {
            Argument::$name($x, $v::$w($y.into()), ArgDisposition::$d(None))
        };
        ($name:ident($x:expr, $v:ident::$w:ident($y:expr), $d:ident($z:expr))) => {
            Argument::$name($x, $v::$w($y.into()), ArgDisposition::$d(Some($z as u8)))
        };
    }

    ArgData! {
        FooFlag,
        Foo(OsString),
        FooPath(PathBuf),
    }

    use self::ArgData::*;

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_arginfo_cmp() {
        let info = flag!("-foo", FooFlag);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Less);
        assert_eq!(info.cmp("-foo="), Ordering::Less);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Less);

        let info = take_arg!("-foo", OsString, Separated, Foo);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Less);
        assert_eq!(info.cmp("-foo="), Ordering::Less);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Less);

        let info = take_arg!("-foo", OsString, Concatenated, Foo);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Equal);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", OsString, Concatenated('='), Foo);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Greater);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", OsString, CanBeSeparated, Foo);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Equal);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", OsString, CanBeSeparated('='), Foo);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Greater);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);
    }

    #[test]
    fn test_arginfo_process() {
        let info = flag!("-foo", FooFlag);
        assert_eq!(
            info.process("-foo", || None).unwrap(),
            arg!(Flag("-foo", FooFlag))
        );

        let info = take_arg!("-foo", OsString, Separated, Foo);
        assert_eq!(
            info.clone().process("-foo", || None).unwrap_err(),
            ArgParseError::UnexpectedEndOfArgs
        );
        assert_eq!(
            info.process("-foo", || Some("bar".into())).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), Separated))
        );

        let info = take_arg!("-foo", OsString, Concatenated, Foo);
        assert_eq!(
            info.clone().process("-foo", || None).unwrap(),
            arg!(WithValue("-foo", Foo(""), Concatenated))
        );
        assert_eq!(
            info.process("-foobar", || None).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), Concatenated))
        );

        let info = take_arg!("-foo", OsString, Concatenated('='), Foo);
        assert_eq!(
            info.clone().process("-foo=", || None).unwrap(),
            arg!(WithValue("-foo", Foo(""), Concatenated('=')))
        );
        assert_eq!(
            info.process("-foo=bar", || None).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), Concatenated('=')))
        );

        let info = take_arg!("-foo", OsString, CanBeSeparated, Foo);
        assert_eq!(
            info.clone().process("-foo", || None).unwrap(),
            arg!(WithValue("-foo", Foo(""), Concatenated))
        );
        assert_eq!(
            info.clone().process("-foobar", || None).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), CanBeSeparated))
        );
        assert_eq!(
            info.process("-foo", || Some("bar".into())).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), CanBeConcatenated))
        );

        let info = take_arg!("-foo", OsString, CanBeSeparated('='), Foo);
        assert_eq!(
            info.clone().process("-foo", || None).unwrap_err(),
            ArgParseError::UnexpectedEndOfArgs
        );
        assert_eq!(
            info.clone().process("-foo=", || None).unwrap(),
            arg!(WithValue("-foo", Foo(""), CanBeSeparated('=')))
        );
        assert_eq!(
            info.clone().process("-foo=bar", || None).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), CanBeSeparated('=')))
        );
        assert_eq!(
            info.process("-foo", || Some("bar".into())).unwrap(),
            arg!(WithValue("-foo", Foo("bar"), CanBeConcatenated('=')))
        );
    }

    #[test]
    fn test_bsearch() {
        let data = vec![
            ("bar", 1),
            ("foo", 2),
            ("fuga", 3),
            ("hoge", 4),
            ("plop", 5),
            ("qux", 6),
            ("zorglub", 7),
        ];
        for item in &data {
            assert_eq!(bsearch(item.0, &data, |i, k| i.0.cmp(k)), Some(item));
        }

        // Try again with an even number of items
        let data = &data[..6];
        for item in data {
            assert_eq!(bsearch(item.0, data, |i, k| i.0.cmp(k)), Some(item));
        }

        // Once more, with prefix matches
        let data = vec![
            ("a", 1),
            ("ab", 2),
            ("abc", 3),
            ("abd", 4),
            ("abe", 5),
            ("abef", 6),
            ("abefg", 7),
        ];
        for item in &data {
            assert_eq!(
                bsearch(item.0, &data, |i, k| if k.starts_with(i.0) {
                    Ordering::Equal
                } else {
                    i.0.cmp(k)
                }),
                Some(item)
            );
        }

        // Try again with an even number of items
        let data = &data[..6];
        for item in data {
            assert_eq!(
                bsearch(item.0, data, |i, k| if k.starts_with(i.0) {
                    Ordering::Equal
                } else {
                    i.0.cmp(k)
                }),
                Some(item)
            );
        }
    }

    #[test]
    fn test_multi_search() {
        static ARGS: [ArgInfo<ArgData>; 1] = [take_arg!("-include", OsString, Concatenated, Foo)];
        static ARGS2: [ArgInfo<ArgData>; 1] =
            [take_arg!("-include-pch", OsString, Concatenated, Foo)];
        static ARGS3: [ArgInfo<ArgData>; 1] =
            [take_arg!("-include", PathBuf, Concatenated, FooPath)];

        assert_eq!((&ARGS[..], &ARGS2[..]).search("-include"), Some(&ARGS[0]));
        assert_eq!(
            (&ARGS[..], &ARGS2[..]).search("-include-pch"),
            Some(&ARGS2[0])
        );
        assert_eq!((&ARGS2[..], &ARGS[..]).search("-include"), Some(&ARGS[0]));
        assert_eq!(
            (&ARGS2[..], &ARGS[..]).search("-include-pch"),
            Some(&ARGS2[0])
        );
        assert_eq!((&ARGS[..], &ARGS3[..]).search("-include"), Some(&ARGS3[0]));
    }

    #[test]
    fn test_argsiter() {
        ArgData! {
            Bar,
            Foo(OsString),
            Fuga,
            Hoge(PathBuf),
            Plop,
            Qux(OsString),
            Zorglub,
        }

        // Need to explicitly refer to enum because `use` doesn't work if it's in a module
        // https://internals.rust-lang.org/t/pre-rfc-support-use-enum-for-function-local-enums/3853/13
        static ARGS: [ArgInfo<ArgData>; 7] = [
            flag!("-bar", ArgData::Bar),
            take_arg!("-foo", OsString, Separated, ArgData::Foo),
            flag!("-fuga", ArgData::Fuga),
            take_arg!("-hoge", PathBuf, Concatenated, ArgData::Hoge),
            flag!("-plop", ArgData::Plop),
            take_arg!("-qux", OsString, CanBeSeparated('='), ArgData::Qux),
            flag!("-zorglub", ArgData::Zorglub),
        ];

        let args = [
            "-nomatch",
            "-foo",
            "value",
            "-hoge",
            "value",       // -hoge doesn't take a separate value
            "-hoge=value", // = is not recognized as a separator
            "-hogevalue",
            "-zorglub",
            "-qux",
            "value",
            "-plop",
            "-quxbar", // -quxbar is not -qux with a value of bar
            "-qux=value",
            "--",
            "non_flag",
            "-flag-after-double-dashes",
        ];
        let iter = ArgsIter::new(args.iter().map(OsString::from), &ARGS[..]).with_double_dashes();
        let expected = vec![
            arg!(UnknownFlag("-nomatch")),
            arg!(WithValue("-foo", ArgData::Foo("value"), Separated)),
            arg!(WithValue("-hoge", ArgData::Hoge(""), Concatenated)),
            arg!(Raw("value")),
            arg!(WithValue("-hoge", ArgData::Hoge("=value"), Concatenated)),
            arg!(WithValue("-hoge", ArgData::Hoge("value"), Concatenated)),
            arg!(Flag("-zorglub", ArgData::Zorglub)),
            arg!(WithValue(
                "-qux",
                ArgData::Qux("value"),
                CanBeConcatenated('=')
            )),
            arg!(Flag("-plop", ArgData::Plop)),
            arg!(UnknownFlag("-quxbar")),
            arg!(WithValue(
                "-qux",
                ArgData::Qux("value"),
                CanBeSeparated('=')
            )),
            arg!(Raw("--")),
            arg!(Raw("non_flag")),
            arg!(Raw("-flag-after-double-dashes")),
        ];
        match diff_with(iter, expected, |a, b| {
            assert_eq!(a.as_ref().unwrap(), b);
            true
        }) {
            None => {}
            Some(Diff::FirstMismatch(_, _, _)) => unreachable!(),
            Some(Diff::Shorter(_, i)) => {
                assert_eq!(i.map(|a| a.unwrap()).collect::<Vec<_>>(), vec![])
            }
            Some(Diff::Longer(_, i)) => {
                assert_eq!(Vec::<Argument<ArgData>>::new(), i.collect::<Vec<_>>())
            }
        }
    }

    // https://github.com/rust-lang/rust-clippy/issues/6550
    #[allow(clippy::from_iter_instead_of_collect)]
    #[test]
    fn test_argument_into_iter() {
        // Needs type annotation or ascription
        let raw: Argument<ArgData> = arg!(Raw("value"));
        let unknown: Argument<ArgData> = arg!(UnknownFlag("-foo"));
        assert_eq!(Vec::from_iter(raw.iter_os_strings()), ovec!["value"]);
        assert_eq!(Vec::from_iter(unknown.iter_os_strings()), ovec!["-foo"]);
        assert_eq!(
            Vec::from_iter(arg!(Flag("-foo", FooFlag)).iter_os_strings()),
            ovec!["-foo"]
        );

        let arg = arg!(WithValue("-foo", Foo("bar"), Concatenated));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foobar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), Concatenated('=')));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foo=bar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), CanBeSeparated));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foobar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), CanBeSeparated('=')));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foo=bar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), CanBeConcatenated));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foo", "bar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), CanBeConcatenated('=')));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foo", "bar"]);

        let arg = arg!(WithValue("-foo", Foo("bar"), Separated));
        assert_eq!(Vec::from_iter(arg.iter_os_strings()), ovec!["-foo", "bar"]);
    }

    #[test]
    fn test_arginfo_process_take_concat_arg_delim_doesnt_crash() {
        let _ = take_arg!("-foo", OsString, Concatenated('='), Foo).process("-foo", || None);
    }

    #[cfg(debug_assertions)]
    mod assert_tests {
        use super::*;

        #[test]
        #[should_panic]
        fn test_arginfo_process_flag() {
            flag!("-foo", FooFlag).process("-bar", || None).unwrap();
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_arg() {
            take_arg!("-foo", OsString, Separated, Foo)
                .process("-bar", || None)
                .unwrap();
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_concat_arg() {
            take_arg!("-foo", OsString, Concatenated, Foo)
                .process("-bar", || None)
                .unwrap();
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_concat_arg_delim() {
            take_arg!("-foo", OsString, Concatenated('='), Foo)
                .process("-bar", || None)
                .unwrap();
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_maybe_concat_arg() {
            take_arg!("-foo", OsString, CanBeSeparated, Foo)
                .process("-bar", || None)
                .unwrap();
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_maybe_concat_arg_delim() {
            take_arg!("-foo", OsString, CanBeSeparated('='), Foo)
                .process("-bar", || None)
                .unwrap();
        }

        #[test]
        #[should_panic]
        fn test_args_iter_unsorted() {
            static ARGS: [ArgInfo<ArgData>; 2] = [flag!("-foo", FooFlag), flag!("-bar", FooFlag)];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }

        #[test]
        #[should_panic]
        fn test_args_iter_unsorted_2() {
            static ARGS: [ArgInfo<ArgData>; 2] = [flag!("-foo", FooFlag), flag!("-foo", FooFlag)];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }

        #[test]
        fn test_args_iter_no_conflict() {
            static ARGS: [ArgInfo<ArgData>; 2] = [flag!("-foo", FooFlag), flag!("-fooz", FooFlag)];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }
    }
}
