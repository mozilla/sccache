// Copyright 2022 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Partially sub-licensed under the MIT license
// Copyright (c) 2016 Alex Burka
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

/**
 * Helper macro to create fixed-length arrays without specifying a static size
 */
#[macro_export]
macro_rules! counted_array {

    //CALL ENTRY

    // provided public array
    (pub $storage:ident $n:ident: [$t:ty; _] = [$($vals:expr),* $(,)*]) => {
        counted_array!(@parse 0usize, ($($vals),*) -> [] ((pub) $storage $n $t));
    };
    // provided private array
    ($storage:ident $n:ident: [$t:ty; _] = [$($vals:expr),* $(,)*]) => {
        counted_array!(@parse 0usize, ($($vals),*) -> [] (() $storage $n $t));
    };


    // RECURSIVE CALLS

    // tail call
    (@parse $size:expr, ($val:expr) -> [$($accs:expr),*] $thru:tt) => {
        counted_array!(@output $size + 1usize, [$($accs,)* $val] $thru);
    };
    // non-tail call
    (@parse $size:expr, ($val:expr, $($vals:expr),*) -> [$($accs:expr),*] $thru:tt) => {
        counted_array!(@parse $size + 1usize, ($($vals),*) -> [$($accs,)* $val] $thru);
    };

    //OUTPUT
    (@output $size:expr, $acc:tt (($($p:tt)*) $s:ident $n:ident $t:ty)) => {
        $($p)* $s $n: [$t; $size] = $acc;
    };
}

#[cfg(test)]
mod counted_array_test {

    #[test]
    fn counted_array_macro() {
        counted_array!(static ARR_QUAD: [u8;_] = [1,2,3,4,]);
        assert_eq!(ARR_QUAD.len(), 4);
    }

    counted_array!(pub const CONST_ARR: [i32; _] = [1, 2, 3]);
    counted_array!(pub static STATIC_ARR: [i32; _] = [7, 8, 9, 10]);

    #[test]
    fn public_arrays() {
        assert_eq!(CONST_ARR, [1, 2, 3]);
        assert_eq!(STATIC_ARR, [7, 8, 9, 10]);
    }

    #[test]
    fn test_public_arrays() {
        public_arrays();
    }
}
