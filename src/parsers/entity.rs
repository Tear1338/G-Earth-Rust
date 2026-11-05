//! Basic position type from the original G-Earth extension API.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HPoint {
    pub x: i32,
    pub y: i32,
    pub z: f64,
}

impl HPoint {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y, z: 0.0 }
    }

    pub fn with_height(x: i32, y: i32, z: f64) -> Self {
        Self { x, y, z }
    }
}

impl fmt::Display for HPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{},{})", self.x, self.y, super::java_double(self.z))
    }
}

#[cfg(test)]
mod tests {
    use super::HPoint;

    #[test]
    fn point_formats_coordinates_like_the_java_api() {
        assert_eq!(HPoint::new(2, -3).to_string(), "(2,-3,0.0)");
        assert_eq!(HPoint::with_height(1, 2, -0.0).to_string(), "(1,2,-0.0)");
        assert_eq!(
            HPoint::with_height(1, 2, 10_000_000.0).to_string(),
            "(1,2,1.0E7)"
        );
        assert_ne!(
            HPoint::with_height(1, 2, f64::NAN),
            HPoint::with_height(1, 2, f64::NAN)
        );
    }
}
