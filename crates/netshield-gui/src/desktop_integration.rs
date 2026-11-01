//! The file manager's icon for the installed binary.
//!
//! A file's icon on Linux is GIO's `standard::icon`, and for an ELF binary that is
//! MIME-derived: `application-x-executable`, whatever the program is and whichever
//! `.desktop` entry names it. There is no icon slot in an ELF and none is consulted. What
//! does work is the file manager's own per-file custom icon -- the GVFS metadata key
//! `metadata::custom-icon`, the key a "Custom Icon" picker writes.
//!
//! The mark is never written beside the binary: `/usr/local/bin` belongs to root and this
//! process does not, so the metadata points into the icon theme `packaging/install.sh`
//! installs. The metadata itself is per-user GVFS state, which is why this runs here rather
//! than in the installer -- an `install.sh` under `sudo` would write it for root.
//!
//! Everything here is best effort: a missing `gio`, an unreadable metadata store or a tree
//! that was never installed only logs. Nothing in this module may fail a launch.

/// Points the file manager's icon for the running executable at the theme's mark.
pub fn install() {
   #[cfg(target_os = "linux")]
   if let Err(err) = linux() {
      log::warn!("file-manager icon: {err}");
   }
}

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

/// The GVFS metadata key the file managers read for a per-file icon.
#[cfg(target_os = "linux")]
const CUSTOM_ICON_KEY: &str = "metadata::custom-icon";

/// The theme's file name for the mark; the desktop entries name it `Icon=netshield`.
#[cfg(target_os = "linux")]
const ICON_NAME: &str = "netshield.png";

/// The theme sizes worth pointing at, largest first: the metadata holds one image and the
/// file manager scales it.
#[cfg(target_os = "linux")]
const THEME_SIZES: [u32; 7] = [256, 128, 64, 48, 32, 24, 16];

/// Records the metadata for this executable, or reports why it could not.
#[cfg(target_os = "linux")]
fn linux() -> Result<(), String> {
   let exe = std::env::current_exe()
      .map_err(|err| format!("cannot resolve the running executable: {err}"))?;
   let Some(mark) = theme_candidates(&theme_roots())
      .into_iter()
      .find(|candidate| candidate.is_file())
   else {
      // Not installed -- a `cargo run` from the tree. There is nothing to point at, and a
      // metadata value naming a file that does not exist is worse than leaving it alone.
      return Ok(());
   };
   apply(&exe, &mark)
}

/// The icon roots to try, in order: the user's data directory first, then the system one.
#[cfg(target_os = "linux")]
fn theme_roots() -> Vec<PathBuf> {
   let mut roots = Vec::new();
   if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
      let dir = PathBuf::from(dir);
      if dir.is_absolute() {
         roots.push(dir);
      }
   } else if let Some(home) = std::env::var_os("HOME") {
      roots.push(PathBuf::from(home).join(".local/share"));
   }
   roots.push(PathBuf::from("/usr/share"));
   roots
}

/// Every path worth trying, in the order they should be tried: root by root, and inside each
/// root the largest size first.
#[cfg(target_os = "linux")]
fn theme_candidates(roots: &[PathBuf]) -> Vec<PathBuf> {
   let mut candidates = Vec::with_capacity(roots.len() * THEME_SIZES.len());
   for root in roots {
      for size in THEME_SIZES {
         candidates.push(root.join(format!("hicolor/{size}x{size}/apps/{ICON_NAME}")));
      }
   }
   candidates
}

/// The metadata currently recorded for `exe`, if any. A path GIO cannot describe simply has
/// none, which is not worth reporting.
#[cfg(target_os = "linux")]
fn current_icon(exe: &Path) -> Option<String> {
   let out = Command::new("gio")
      .arg("info")
      .arg("-a")
      .arg(CUSTOM_ICON_KEY)
      .arg(exe)
      .output()
      .ok()?;
   if !out.status.success() {
      return None;
   }
   let key = format!("{CUSTOM_ICON_KEY}:");
   String::from_utf8_lossy(&out.stdout)
      .lines()
      .find_map(|line| line.trim().strip_prefix(&key))
      .map(|value| value.trim().to_owned())
}

/// Writes the metadata, touching it only when it is not already right: an up-to-date install
/// costs one `gio info` read per launch.
#[cfg(target_os = "linux")]
fn apply(exe: &Path, mark: &Path) -> Result<(), String> {
   let uri = file_uri(mark);
   if current_icon(exe).as_deref() == Some(uri.as_str()) {
      return Ok(());
   }
   let out = Command::new("gio")
      .arg("set")
      .arg(exe)
      .arg(CUSTOM_ICON_KEY)
      .arg(&uri)
      .output()
      .map_err(|err| format!("cannot run `gio` (is glib installed?): {err}"))?;
   if !out.status.success() {
      return Err(format!(
         "`gio set` failed: {}",
         String::from_utf8_lossy(&out.stderr).trim()
      ));
   }
   log::info!(
      "set the file-manager icon of {} to {uri}",
      exe.display()
   );
   Ok(())
}

/// A `file://` URI for `path`, percent-encoding everything outside the unreserved set so a
/// directory with a space or a non-UTF-8 byte still resolves: the metadata is keyed by URI
/// and the file manager decodes it with `g_filename_from_uri`.
#[cfg(target_os = "linux")]
fn file_uri(path: &Path) -> String {
   use std::os::unix::ffi::OsStrExt;

   const HEX: &[u8; 16] = b"0123456789ABCDEF";

   let mut uri = String::from("file://");
   for &byte in path.as_os_str().as_bytes() {
      if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
         uri.push(byte as char);
      } else {
         uri.push('%');
         uri.push(HEX[usize::from(byte >> 4)] as char);
         uri.push(HEX[usize::from(byte & 0x0F)] as char);
      }
   }
   uri
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
   use super::*;

   #[test]
   fn a_uri_escapes_what_the_metadata_key_cannot_carry() {
      assert_eq!(
         file_uri(Path::new(
            "/usr/share/icons/hicolor/256x256/apps/netshield.png"
         )),
         "file:///usr/share/icons/hicolor/256x256/apps/netshield.png"
      );
      assert_eq!(
         file_uri(Path::new("/tmp/feta recipe/x y.png")),
         "file:///tmp/feta%20recipe/x%20y.png"
      );
      assert_eq!(
         file_uri(Path::new("/tmp/\u{e9}.png")),
         "file:///tmp/%C3%A9.png"
      );
   }

   #[test]
   fn the_theme_lookup_tries_the_user_directory_first_and_the_largest_size_first() {
      let roots = [
         PathBuf::from("/home/x/.local/share"),
         PathBuf::from("/usr/share"),
      ];
      let candidates = theme_candidates(&roots);
      assert_eq!(
         candidates.first(),
         Some(&PathBuf::from(
            "/home/x/.local/share/hicolor/256x256/apps/netshield.png"
         ))
      );
      assert_eq!(
         candidates.last(),
         Some(&PathBuf::from(
            "/usr/share/hicolor/16x16/apps/netshield.png"
         ))
      );
      assert_eq!(candidates.len(), 2 * THEME_SIZES.len());
   }
}
