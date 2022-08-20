/// Helper macro to create fixed-length arrays without specifying a fixed size
#[macro_export]
macro_rules! counted_array {
    ($v:vis static $name:ident : [ $t:ty ; _ ] = [$($value:expr),* $(,)?] ) => {
        $v static $name : [
            $t;
            counted_array!(@count $($value,)*)
        ] = [
            $( $value ),*
        ];
    };
    // The best way to count variadic args
    // according to <https://github.com/rust-lang/lang-team/issues/28>
    (@count ) => { 0usize };
    (@count $($arg:expr,)*) => {
        <[()]>::len(&[ $( counted_array!( @nil $arg ), )*])
    };

    (@nil $orig:expr) => {
        ()
    };
}

#[cfg(test)]
mod test {
    #[test]
    fn counted_array_macro() {
        counted_array!(static ARR_QUAD: [u8;_] = [1,2,3,4,]);
        assert_eq!(ARR_QUAD.len(), 4);
    }
}
