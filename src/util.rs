use std::fmt::{Debug, Display};

pub struct SwapDebugAndDisplay<T>(pub T);

impl<T: Display> Debug for SwapDebugAndDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: Debug> Display for SwapDebugAndDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}
