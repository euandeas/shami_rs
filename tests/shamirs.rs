use shami_rs::shamirs::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamirs_simple() {
        for _ in 0..5 {
            assert_eq!(
                "Hello! Testing!".as_bytes().to_vec(),
                rebuild_secret(build_shares("Hello! Testing!", 3, 5))
            );
        }
    }
}
