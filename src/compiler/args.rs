use std::cmp::Ordering;
use std::ffi::OsString;
use std::path::PathBuf;

pub type Delimiter = Option<u8>;

/// Representation of a parsed argument
#[derive(PartialEq, Clone, Debug)]
pub enum Argument {
    /// Unknown non-flag argument ; e.g. "foo"
    Raw(OsString),
    /// Unknown flag argument ; e.g. "-foo"
    UnknownFlag(OsString),
    /// Known flag argument ; e.g. "-bar"
    Flag(&'static str),
    /// Known argument with a value ; e.g. "-qux bar", where the way the
    /// value is passed is described by the ArgDisposition type.
    WithValue(&'static str, ArgumentValue, ArgDisposition),
}

/// How a value is passed to an argument with a value.
#[derive(PartialEq, Clone, Debug)]
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

impl Argument {
    /// For arguments that allow both a concatenated or separated disposition,
    /// normalize a parsed argument to a prefered disposition.
    pub fn normalize(self, disposition: NormalizedDisposition) -> Self {
        match self {
            Argument::WithValue(s, v, ArgDisposition::CanBeConcatenated(d)) |
            Argument::WithValue(s, v, ArgDisposition::CanBeSeparated(d)) => {
                Argument::WithValue(
                    s,
                    v,
                    match disposition {
                        NormalizedDisposition::Separated => ArgDisposition::Separated,
                        NormalizedDisposition::Concatenated => ArgDisposition::Concatenated(d),
                    },
                )
            }
            a => a,
        }
    }

    pub fn to_os_string(&self) -> OsString {
        match *self {
            Argument::Raw(ref s) |
            Argument::UnknownFlag(ref s) => s.clone(),
            Argument::Flag(ref s) |
            Argument::WithValue(ref s, _, _) => s.into(),
        }
    }

    pub fn to_str(&self) -> Option<&'static str> {
        match *self {
            Argument::Flag(s) |
            Argument::WithValue(s, _, _) => Some(s),
            _ => None,
        }
    }

    pub fn get_value(&self) -> Option<ArgumentValue> {
        match *self {
            Argument::WithValue(_, ref v, _) => Some(v.clone()),
            _ => None,
        }
    }
}

pub struct IntoIter {
    arg: Argument,
    emitted: usize,
}

/// Transforms a parsed argument into an iterator.
impl IntoIterator for Argument {
    type Item = OsString;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            arg: self,
            emitted: 0,
        }
    }
}

impl Iterator for IntoIter {
    type Item = OsString;

    fn next(&mut self) -> Option<Self::Item> {
        let result = match self.arg {
            Argument::Raw(ref s) |
            Argument::UnknownFlag(ref s) => {
                match self.emitted {
                    0 => Some(s.clone()),
                    _ => None,
                }
            }
            Argument::Flag(s) => {
                match self.emitted {
                    0 => Some(s.into()),
                    _ => None,
                }
            }
            Argument::WithValue(s, ref v, ref d) => {
                match (self.emitted, d) {
                    (0, &ArgDisposition::CanBeSeparated(d)) |
                    (0, &ArgDisposition::Concatenated(d)) => {
                        let mut s = OsString::from(s);
                        if let Some(d) = d {
                            s.push(OsString::from(String::from_utf8(vec![d]).expect(
                                "delimiter should be ascii",
                            )));
                        }
                        s.push(OsString::from(v.clone()));
                        Some(s)
                    }
                    (0, &ArgDisposition::Separated) |
                    (0, &ArgDisposition::CanBeConcatenated(_)) => Some(s.into()),
                    (1, &ArgDisposition::Separated) |
                    (1, &ArgDisposition::CanBeConcatenated(_)) => Some(v.clone().into()),
                    _ => None,
                }
            }
        };
        if let Some(_) = result {
            self.emitted += 1;
        }
        result
    }
}

/// The value associated with a parsed argument
#[derive(PartialEq, Clone, Debug)]
pub enum ArgumentValue {
    String(OsString),
    PathVal(PathBuf),
}

impl From<ArgumentValue> for OsString {
    fn from(a: ArgumentValue) -> OsString {
        match a {
            ArgumentValue::String(s) => s,
            ArgumentValue::PathVal(p) => p.into(),
        }
    }
}

impl ArgumentValue {
    pub fn unwrap_path(self) -> PathBuf {
        match self {
            ArgumentValue::PathVal(p) => p,
            ArgumentValue::String(_) => panic!("Can't unwrap_path an ArgumentValue::String"),
        }
    }
}


/// The description of how an argument may be parsed
#[derive(PartialEq, Clone, Debug)]
pub enum ArgInfo {
    /// An simple flag argument, of the form "-foo"
    Flag(&'static str),
    /// An argument with a value ; e.g. "-qux bar", where the way the
    /// value is passed is described by the ArgDisposition type.
    TakeArg(&'static str, ArgType, ArgDisposition),
}

/// The type of value associated with an argument
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum ArgType {
    String,
    Path,
}

impl ArgInfo {
    /// Transform an argument description into a parsed Argument, given a
    /// string. For arguments with a value, where the value is separate, the
    /// `get_next_arg` function returns the next argument, in raw `OsString`
    /// form.
    fn process<F>(self, arg: &str, get_next_arg: F) -> Argument
    where
        F: FnOnce() -> Option<OsString>,
    {
        match self {
            ArgInfo::Flag(s) => {
                debug_assert_eq!(s, arg);
                Argument::Flag(s)
            }
            ArgInfo::TakeArg(s, t, ArgDisposition::Separated) => {
                debug_assert_eq!(s, arg);
                if let Some(a) = get_next_arg() {
                    Argument::WithValue(s, t.process(a), ArgDisposition::Separated)
                } else {
                    Argument::Flag(s)
                }
            }
            ArgInfo::TakeArg(s, t, ArgDisposition::Concatenated(d)) => {
                let mut len = s.len();
                debug_assert_eq!(&arg[..len], s);
                if let Some(d) = d {
                    debug_assert_eq!(arg.as_bytes()[len], d);
                    len += 1;
                }
                Argument::WithValue(
                    s,
                    t.process(arg[len..].into()),
                    ArgDisposition::Concatenated(d),
                )
            }
            ArgInfo::TakeArg(s, t, ArgDisposition::CanBeSeparated(d)) |
            ArgInfo::TakeArg(s, t, ArgDisposition::CanBeConcatenated(d)) => {
                let derived = if arg == s {
                    ArgInfo::TakeArg(s, t, ArgDisposition::Separated)
                } else {
                    ArgInfo::TakeArg(s, t, ArgDisposition::Concatenated(d))
                };
                match derived.process(arg, get_next_arg) {
                    Argument::Flag(_) if d == None => {
                        Argument::WithValue(
                            s,
                            t.process("".into()),
                            ArgDisposition::Concatenated(d),
                        )
                    }
                    Argument::WithValue(s, v, ArgDisposition::Concatenated(d)) => {
                        Argument::WithValue(s, v, ArgDisposition::CanBeSeparated(d))
                    }
                    Argument::WithValue(s, v, ArgDisposition::Separated) => {
                        Argument::WithValue(s, v, ArgDisposition::CanBeConcatenated(d))
                    }
                    a => a,
                }
            }
        }
    }

    /// Returns whether the given string matches the argument description, and if not,
    /// how it differs.
    fn cmp(&self, arg: &str) -> Ordering {
        match self {
            &ArgInfo::TakeArg(s, _, ArgDisposition::CanBeSeparated(None)) |
            &ArgInfo::TakeArg(s, _, ArgDisposition::Concatenated(None)) if arg.starts_with(s) => {
                Ordering::Equal
            }
            &ArgInfo::TakeArg(s, _, ArgDisposition::CanBeSeparated(Some(d))) |
            &ArgInfo::TakeArg(s, _, ArgDisposition::Concatenated(Some(d)))
                if arg.len() > s.len() && arg.starts_with(s) => arg.as_bytes()[s.len()].cmp(&d),
            _ => self.as_str().cmp(arg),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            &ArgInfo::Flag(s) |
            &ArgInfo::TakeArg(s, _, _) => s,
        }
    }
}

impl ArgType {
    /// Transform an argument type description into a parsed argument value
    /// given a raw `OsString` value.
    fn process(self, value: OsString) -> ArgumentValue {
        match self {
            ArgType::String => ArgumentValue::String(value),
            ArgType::Path => ArgumentValue::PathVal(value.into()),
        }
    }
}

/// Binary search for a `key` in a sorted array of items, given a comparison
/// function. This implementation is tweaked to handle the case where the
/// comparison function does prefix matching, where multiple items in the array
/// might match, but the last match is the one actually matching.
fn bsearch<'a, K, T, F>(key: K, items: &'a [T], cmp: F) -> Option<&'a T>
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

/// Trait describing types that embed both an ArgInfo and some extra data.
pub trait EmbedsArgInfo {
    type ExtraData;

    fn get_arg_info(&self) -> ArgInfo;
    fn get_extra(&self) -> Self::ExtraData;
}

impl EmbedsArgInfo for ArgInfo {
    type ExtraData = ();

    fn get_arg_info(&self) -> ArgInfo {
        self.clone()
    }

    fn get_extra(&self) -> Self::ExtraData {
        ()
    }
}

impl<T> EmbedsArgInfo for (ArgInfo, T)
where
    T: Clone,
{
    type ExtraData = T;

    fn get_arg_info(&self) -> ArgInfo {
        self.0.clone()
    }

    fn get_extra(&self) -> Self::ExtraData {
        self.1.clone()
    }
}

/// Trait for generically search over a "set" of ArgInfos.
pub trait SearchableArgInfo {
    type Info;

    fn search(&self, key: &str) -> Option<&Self::Info>;

    #[cfg(debug_assertions)]
    fn check(&self) -> bool;
}

/// Allow to search over a sorted array of ArgInfo items associated with extra
/// data.
impl<T> SearchableArgInfo for &'static [T]
where
    T: 'static + EmbedsArgInfo,
{
    type Info = T;

    fn search(&self, key: &str) -> Option<&Self::Info> {
        bsearch(key, self, |i, k| i.get_arg_info().cmp(k))
    }

    #[cfg(debug_assertions)]
    fn check(&self) -> bool {
        self.windows(2).all(|w| {
            let a = w[0].get_arg_info().as_str();
            let b = w[1].get_arg_info().as_str();
            assert!(a < b, "{} can't precede {}", a, b);
            true
        })
    }
}

/// Allow to search over a couple of arrays of ArgInfo, where the second
/// complements or overrides the first one.
impl<T> SearchableArgInfo for (&'static [T], &'static [T])
where
    T: 'static + EmbedsArgInfo,
{
    type Info = T;

    fn search(&self, key: &str) -> Option<&Self::Info> {
        match (self.0.search(key), self.1.search(key)) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(a)) => Some(a),
            (Some(a), Some(b)) => {
                if a.get_arg_info().as_str() > b.get_arg_info().as_str() {
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
    T: 'static + EmbedsArgInfo,
    S: SearchableArgInfo<Info = T>,
{
    arguments: I,
    arg_info: S,
}

impl<I, T, S> ArgsIter<I, T, S>
where
    I: Iterator<Item = OsString>,
    T: 'static + EmbedsArgInfo,
    S: SearchableArgInfo<Info = T>,
{
    /// Create an `Iterator` for parsed arguments, given an iterator of raw
    /// `OsString` arguments, and argument descriptions.
    pub fn new(arguments: I, arg_info: S) -> Self {
        #[cfg(debug_assertions)]
        debug_assert!(arg_info.check());
        ArgsIter {
            arguments: arguments,
            arg_info: arg_info,
        }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub struct ArgumentItem<T> {
    pub arg: Argument,
    pub data: Option<T>,
}

impl<I, T, S, U> Iterator for ArgsIter<I, T, S>
where
    I: Iterator<Item = OsString>,
    T: 'static + EmbedsArgInfo<ExtraData = U>,
    S: SearchableArgInfo<Info = T>,
{
    type Item = ArgumentItem<T::ExtraData>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(arg) = self.arguments.next() {
            let s = arg.to_string_lossy();
            let arguments = &mut self.arguments;
            match self.arg_info.search(&s[..]) {
                Some(ref i) => {
                    Some(ArgumentItem {
                        arg: i.get_arg_info().process(&s[..], || arguments.next()),
                        data: Some(i.get_extra()),
                    })
                }
                None => {
                    Some(ArgumentItem {
                        arg: if s.starts_with("-") {
                            Argument::UnknownFlag(arg.clone())
                        } else {
                            Argument::Raw(arg.clone())
                        },
                        data: None,
                    })
                }
            }
        } else {
            None
        }
    }
}

/// Helper macro used to define ArgInfo::Flag's.
///     flag!("-foo")
///     flag!("-foo", extra_data)
macro_rules! flag {
    ($s:expr) => { ArgInfo::Flag($s) };
    ($s:expr, $d:expr) => { (flag!($s), $d) };
}

/// Helper macro used to define ArgInfo::TakeArg's.
///     take_arg!("-foo", String, Separated)
///     take_arg!("-foo", String, Concatenated)
///     take_arg!("-foo", String, Concatenated('='))
///     take_arg!("-foo", String, Separated, extra_data)
///     take_arg!("-foo", String, Concatenated, extra_data)
///     take_arg!("-foo", String, Concatenated('='), extra_data)
macro_rules! take_arg {
    ($s:expr, $v:ident, Separated) => {
        ArgInfo::TakeArg($s, ArgType::$v, ArgDisposition::Separated)
    };
    ($s:expr, $v:ident, $d:ident) => {
        ArgInfo::TakeArg($s, ArgType::$v, ArgDisposition::$d(None))
    };
    ($s:expr, $v:ident, $d:ident($x:expr)) => {
        ArgInfo::TakeArg($s, ArgType::$v, ArgDisposition::$d(Some($x as u8)))
    };
    ($s:expr, $v:ident, $d:ident($x:expr), $data:expr) => {
        (take_arg!($s, $v, $d($x)), $data)
    };
    ($s:expr, $v:ident, $d:ident, $data:expr) => {
        (take_arg!($s, $v, $d), $data)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;
    use itertools::{diff_with, Diff};

    macro_rules! arg {
        ($name:ident($x:expr)) => {
            Argument::$name($x.into())
         };
        ($name:ident($x:expr, $v:ident($y:expr), Separated)) => {
            Argument::$name($x, ArgumentValue::$v($y.into()), ArgDisposition::Separated)
        };
        ($name:ident($x:expr, $v:ident($y:expr), $d:ident)) => {
            Argument::$name($x, ArgumentValue::$v($y.into()), ArgDisposition::$d(None))
        };
        ($name:ident($x:expr, $v:ident($y:expr), $d:ident($z:expr))) => {
            Argument::$name($x, ArgumentValue::$v($y.into()), ArgDisposition::$d(Some($z as u8)))
        };
    }

    #[test]
    fn test_arginfo_cmp() {
        let info = flag!("-foo");
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Less);
        assert_eq!(info.cmp("-foo="), Ordering::Less);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Less);

        let info = take_arg!("-foo", String, Separated);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Less);
        assert_eq!(info.cmp("-foo="), Ordering::Less);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Less);

        let info = take_arg!("-foo", String, Concatenated);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Equal);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", String, Concatenated('='));
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Greater);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", String, CanBeSeparated);
        assert_eq!(info.cmp("-foo"), Ordering::Equal);
        assert_eq!(info.cmp("bar"), Ordering::Less);
        assert_eq!(info.cmp("-bar"), Ordering::Greater);
        assert_eq!(info.cmp("-qux"), Ordering::Less);
        assert_eq!(info.cmp("-foobar"), Ordering::Equal);
        assert_eq!(info.cmp("-foo="), Ordering::Equal);
        assert_eq!(info.cmp("-foo=bar"), Ordering::Equal);

        let info = take_arg!("-foo", String, CanBeSeparated('='));
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
        let info = flag!("-foo");
        assert_eq!(info.process("-foo", || None), arg!(Flag("-foo")));

        let info = take_arg!("-foo", String, Separated);
        assert_eq!(info.clone().process("-foo", || None), arg!(Flag("-foo")));
        assert_eq!(
            info.clone().process("-foo", || Some("bar".into())),
            arg!(WithValue("-foo", String("bar"), Separated))
        );

        let info = take_arg!("-foo", String, Concatenated);
        assert_eq!(
            info.clone().process("-foo", || None),
            arg!(WithValue("-foo", String(""), Concatenated))
        );
        assert_eq!(
            info.clone().process("-foobar", || None),
            arg!(WithValue("-foo", String("bar"), Concatenated))
        );

        let info = take_arg!("-foo", String, Concatenated('='));
        assert_eq!(
            info.clone().process("-foo=", || None),
            arg!(WithValue("-foo", String(""), Concatenated('=')))
        );
        assert_eq!(
            info.clone().process("-foo=bar", || None),
            arg!(WithValue("-foo", String("bar"), Concatenated('=')))
        );

        let info = take_arg!("-foo", String, CanBeSeparated);
        assert_eq!(
            info.clone().process("-foo", || None),
            arg!(WithValue("-foo", String(""), Concatenated))
        );
        assert_eq!(
            info.clone().process("-foobar", || None),
            arg!(WithValue("-foo", String("bar"), CanBeSeparated))
        );
        assert_eq!(
            info.clone().process("-foo", || Some("bar".into())),
            arg!(WithValue("-foo", String("bar"), CanBeConcatenated))
        );

        let info = take_arg!("-foo", String, CanBeSeparated('='));
        assert_eq!(info.clone().process("-foo", || None), arg!(Flag("-foo")));
        assert_eq!(
            info.clone().process("-foo=", || None),
            arg!(WithValue("-foo", String(""), CanBeSeparated('=')))
        );
        assert_eq!(
            info.clone().process("-foo=bar", || None),
            arg!(WithValue("-foo", String("bar"), CanBeSeparated('=')))
        );
        assert_eq!(
            info.clone().process("-foo", || Some("bar".into())),
            arg!(WithValue("-foo", String("bar"), CanBeConcatenated('=')))
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
            assert_eq!(bsearch(item.0, &data, |i, k| i.0.cmp(k)), Some(item));
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
                bsearch(item.0, &data, |i, k| if k.starts_with(i.0) {
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
        static ARGS: [ArgInfo; 1] = [take_arg!("-include", String, Concatenated)];
        static ARGS2: [ArgInfo; 1] = [take_arg!("-include-pch", String, Concatenated)];
        static ARGS3: [ArgInfo; 1] = [take_arg!("-include", Path, Concatenated)];

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
        static ARGS: [(ArgInfo, u8); 7] = [
            flag!("-bar", 1),
            take_arg!("-foo", String, Separated, 2),
            flag!("-fuga", 3),
            take_arg!("-hoge", Path, Concatenated, 4),
            flag!("-plop", 5),
            take_arg!("-qux", String, CanBeSeparated('='), 6),
            flag!("-zorglub", 7),
        ];

        let args = [
            "-nomatch",
            "-foo",
            "value",
            "-hoge",
            "value", // -hoge doesn't take a separate value
            "-hoge=value", // = is not recognized as a separator
            "-hogevalue",
            "-zorglub",
            "-qux",
            "value",
            "-plop",
            "-quxbar", // -quxbar is not -qux with a value of bar
            "-qux=value",
        ];
        let iter = ArgsIter::new(args.into_iter().map(OsString::from), &ARGS[..]);
        let expected = vec![
            ArgumentItem {
                arg: arg!(UnknownFlag("-nomatch")),
                data: None,
            },
            ArgumentItem {
                arg: arg!(WithValue("-foo", String("value"), Separated)),
                data: Some(2),
            },
            ArgumentItem {
                arg: arg!(WithValue("-hoge", PathVal(""), Concatenated)),
                data: Some(4),
            },
            ArgumentItem {
                arg: arg!(Raw("value")),
                data: None,
            },
            ArgumentItem {
                arg: arg!(WithValue("-hoge", PathVal("=value"), Concatenated)),
                data: Some(4),
            },
            ArgumentItem {
                arg: arg!(WithValue("-hoge", PathVal("value"), Concatenated)),
                data: Some(4),
            },
            ArgumentItem {
                arg: arg!(Flag("-zorglub")),
                data: Some(7),
            },
            ArgumentItem {
                arg: arg!(WithValue("-qux", String("value"), CanBeConcatenated('='))),
                data: Some(6),
            },
            ArgumentItem {
                arg: arg!(Flag("-plop")),
                data: Some(5),
            },
            ArgumentItem {
                arg: arg!(UnknownFlag("-quxbar")),
                data: None,
            },
            ArgumentItem {
                arg: arg!(WithValue("-qux", String("value"), CanBeSeparated('='))),
                data: Some(6),
            },
        ];
        match diff_with(iter, expected, |ref a, ref b| {
            assert_eq!(a, b);
            true
        }) {
            None => {}
            Some(Diff::FirstMismatch(_, _, _)) => unreachable!(),
            Some(Diff::Shorter(_, i)) => assert_eq!(i.collect::<Vec<_>>(), vec![]),
            Some(Diff::Longer(_, i)) => {
                assert_eq!(Vec::<ArgumentItem<u8>>::new(), i.collect::<Vec<_>>())
            }
        }
    }

    #[test]
    fn test_argument_into_iter() {
        assert_eq!(Vec::from_iter(arg!(Raw("value"))), ovec!["value"]);
        assert_eq!(Vec::from_iter(arg!(UnknownFlag("-foo"))), ovec!["-foo"]);
        assert_eq!(Vec::from_iter(arg!(Flag("-foo"))), ovec!["-foo"]);

        let arg = arg!(WithValue("-foo", String("bar"), Concatenated));
        assert_eq!(Vec::from_iter(arg), ovec!["-foobar"]);

        let arg = arg!(WithValue("-foo", String("bar"), Concatenated('=')));
        assert_eq!(Vec::from_iter(arg), ovec!["-foo=bar"]);

        let arg = arg!(WithValue("-foo", String("bar"), CanBeSeparated));
        assert_eq!(Vec::from_iter(arg), ovec!["-foobar"]);

        let arg = arg!(WithValue("-foo", String("bar"), CanBeSeparated('=')));
        assert_eq!(Vec::from_iter(arg), ovec!["-foo=bar"]);

        let arg = arg!(WithValue("-foo", String("bar"), CanBeConcatenated));
        assert_eq!(Vec::from_iter(arg), ovec!["-foo", "bar"]);

        let arg = arg!(WithValue("-foo", String("bar"), CanBeConcatenated('=')));
        assert_eq!(Vec::from_iter(arg), ovec!["-foo", "bar"]);

        let arg = arg!(WithValue("-foo", String("bar"), Separated));
        assert_eq!(Vec::from_iter(arg), ovec!["-foo", "bar"]);
    }

    #[cfg(debug_assertions)]
    mod assert_tests {
        use super::*;

        #[test]
        #[should_panic]
        fn test_arginfo_process_flag() {
            flag!("-foo").process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_arg() {
            take_arg!("-foo", String, Separated).process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_concat_arg() {
            take_arg!("-foo", String, Concatenated).process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_concat_arg_delim() {
            take_arg!("-foo", String, Concatenated('=')).process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_concat_arg_delim_same() {
            take_arg!("-foo", String, Concatenated('=')).process("-foo", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_maybe_concat_arg() {
            take_arg!("-foo", String, CanBeSeparated).process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_arginfo_process_take_maybe_concat_arg_delim() {
            take_arg!("-foo", String, CanBeSeparated('=')).process("-bar", || None);
        }

        #[test]
        #[should_panic]
        fn test_args_iter_unsorted() {
            static ARGS: [ArgInfo; 2] = [flag!("-foo"), flag!("-bar")];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }

        #[test]
        #[should_panic]
        fn test_args_iter_unsorted_2() {
            static ARGS: [ArgInfo; 2] = [flag!("-foo"), flag!("-foo")];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }

        #[test]
        fn test_args_iter_no_conflict() {
            static ARGS: [ArgInfo; 2] = [flag!("-foo"), flag!("-fooz")];
            ArgsIter::new(Vec::<OsString>::new().into_iter(), &ARGS[..]);
        }
    }
}
