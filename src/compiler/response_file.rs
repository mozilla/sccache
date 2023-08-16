
/// An iterator over the arguments in a Windows command line.
///
/// This produces results identical to `CommandLineToArgvW` except in the
/// following cases:
///
///  1. When passed an empty string, CommandLineToArgvW returns the path to the
///     current executable file. Here, the iterator will simply be empty.
///  2. CommandLineToArgvW interprets the first argument differently than the
///     rest. Here, all arguments are treated in identical fashion.
///
/// Parsing rules:
///
///  - Arguments are delimited by whitespace (either a space or tab).
///  - A string surrounded by double quotes is interpreted as a single argument.
///  - Backslashes are interpreted literally unless followed by a double quote.
///  - 2n backslashes followed by a double quote reduce to n backslashes and we
///    enter the "in quote" state.
///  - 2n+1 backslashes followed by a double quote reduces to n backslashes,
///    we do *not* enter the "in quote" state, and the double quote is
///    interpreted literally.
///
/// References:
///  - https://msdn.microsoft.com/en-us/library/windows/desktop/bb776391(v=vs.85).aspx
///  - https://msdn.microsoft.com/en-us/library/windows/desktop/17w5ykft(v=vs.85).aspx
#[derive(Clone, Debug)]
pub struct SplitMsvcResponseFileArgs<'a> {
    /// String slice of the file content that is being parsed.
    /// Slice is mutated as this iterator is executed.
    file_content: &'a str,
}

impl<'a, T> From<&'a T> for SplitMsvcResponseFileArgs<'a>
where
    T: AsRef<str> + 'static,
{
    fn from(file_content: &'a T) -> Self {
        Self {
            file_content: file_content.as_ref(),
        }
    }
}

impl<'a> SplitMsvcResponseFileArgs<'a> {
    /// Appends backslashes to `target` by decrementing `count`.
    /// If `step` is >1, then `count` is decremented by `step`, resulting in 1 backslash appended for every `step`.
    fn append_backslashes_to(target: &mut String, count: &mut usize, step: usize) {
        while *count >= step {
            target.push('\\');
            *count -= step;
        }
    }
}

impl<'a> Iterator for SplitMsvcResponseFileArgs<'a> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut in_quotes = false;
        let mut backslash_count: usize = 0;

        // Strip any leading whitespace before relevant characters
        let is_whitespace = |c| matches!(c, ' ' | '\t' | '\n' | '\r');
        self.file_content = self.file_content.trim_start_matches(is_whitespace);

        if self.file_content.is_empty() {
            return None;
        }

        // The argument string to return, built by analyzing the current slice in the iterator.
        let mut arg = String::new();
        // All characters still in the string slice. Will be mutated by consuming
        // values until the current arg is built.
        let mut chars = self.file_content.chars();
        // Build the argument by evaluating each character in the string slice.
        for c in &mut chars {
            match c {
                // In order to handle the escape character based on the char(s) which come after it,
                // they are counted instead of appended literally, until a non-backslash character is encountered.
                '\\' => backslash_count += 1,
                // Either starting or ending a quoted argument, or appending a literal character (if the quote was escaped).
                '"' => {
                    // Only append half the number of backslashes encountered, because this is an escaped string.
                    // This will reduce `backslash_count` to either 0 or 1.
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 2);
                    match backslash_count == 0 {
                        // If there are no remaining encountered backslashes,
                        // then we have found either the start or end of a quoted argument.
                        true => in_quotes = !in_quotes,
                        // The quote character is escaped, so it is treated as a literal and appended to the arg string.
                        false => {
                            backslash_count = 0;
                            arg.push('"');
                        }
                    }
                }
                // If whitespace is encountered, only preserve it if we are currently in quotes.
                // Otherwise it marks the end of the current argument.
                ' ' | '\t' | '\n' | '\r' => {
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
                    // If not in a quoted string, then this is the end of the argument.
                    if !in_quotes {
                        break;
                    }
                    // Otherwise, the whitespace must be preserved in the argument.
                    arg.push(c);
                }
                // All other characters treated as is
                _ => {
                    Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
                    arg.push(c);
                }
            }
        }

        // Flush any backslashes at the end of the string.
        Self::append_backslashes_to(&mut arg, &mut backslash_count, 1);
        // Save the current remaining characters for the next step in the iterator.
        self.file_content = chars.as_str();

        Some(arg)
    }
}
