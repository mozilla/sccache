fn unused() {}

pub fn env_dep_test() {
    println!("Env var: {}", env!("TEST_ENV_VAR"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
